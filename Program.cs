using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Reactive.Linq;
using System.Reactive.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace PrivateWorkingSet
{
    class Program
    {
        [DllImport("ntdll.dll", ExactSpelling = true)]
        internal static extern unsafe uint NtQuerySystemInformation(int SystemInformationClass, void* SystemInformation, uint SystemInformationLength, uint* ReturnLength);

        internal const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

        internal static int SystemProcessID
        {
            get
            {
                const int systemProcessIDOnXP = 4;
                return systemProcessIDOnXP;
            }
        }

        internal const int IdleProcessID = 0;

        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa380518.aspx
        // https://msdn.microsoft.com/en-us/library/windows/hardware/ff564879.aspx
        [StructLayout(LayoutKind.Sequential)]
        internal struct UNICODE_STRING
        {
            /// <summary>
            /// Length in bytes, not including the null terminator, if any.
            /// </summary>
            internal ushort Length;

            /// <summary>
            /// Max size of the buffer in bytes
            /// </summary>
            internal ushort MaximumLength;
            internal IntPtr Buffer;
        }


        // From SYSTEM_INFORMATION_CLASS
        // Use for NtQuerySystemInformation
        internal const int SystemProcessInformation = 5;

        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct SYSTEM_PROCESS_INFORMATION
        {
            internal uint NextEntryOffset;
            internal uint NumberOfThreads;
            internal long WorkingSetPrivateSize;
            private fixed byte Reserved1[24];//private fixed byte Reserved1[48];
            internal long UserTime;
            internal long KernelTime;
            internal UNICODE_STRING ImageName;
            internal int BasePriority;
            internal IntPtr UniqueProcessId;
            private readonly UIntPtr Reserved2;
            internal uint HandleCount;
            internal uint SessionId;
            private readonly UIntPtr Reserved3;
            internal UIntPtr PeakVirtualSize;  // SIZE_T
            internal UIntPtr VirtualSize;
            private readonly uint Reserved4;
            internal UIntPtr PeakWorkingSetSize;  // SIZE_T
            internal UIntPtr WorkingSetSize;  // SIZE_T
            private readonly UIntPtr Reserved5;
            internal UIntPtr QuotaPagedPoolUsage;  // SIZE_T
            private readonly UIntPtr Reserved6;
            internal UIntPtr QuotaNonPagedPoolUsage;  // SIZE_T
            internal UIntPtr PagefileUsage;  // SIZE_T
            internal UIntPtr PeakPagefileUsage;  // SIZE_T
            internal UIntPtr PrivatePageCount;  // SIZE_T
            private fixed long Reserved7[6];
        }

        internal sealed class ProcessInfo
        {
            internal int BasePriority { get; set; }
            internal string ProcessName { get; set; } = string.Empty;
            internal int ProcessId { get; set; }
            internal long PoolPagedBytes { get; set; }
            internal long PoolNonPagedBytes { get; set; }
            internal long VirtualBytes { get; set; }
            internal long VirtualBytesPeak { get; set; }
            internal long WorkingSetPeak { get; set; }
            internal long WorkingSet { get; set; }
            internal long PageFileBytesPeak { get; set; }
            internal long PageFileBytes { get; set; }
            internal long PrivateBytes { get; set; }
            internal int SessionId { get; set; }
            internal int HandleCount { get; set; }

            internal int NumerOfThread { get; set; }

            internal long UserTime { get; set; }
            internal long KernelTime { get; set; }
            internal long TotalTime { get { return UserTime + KernelTime; } }

            internal long PrivateWorkingSet { get; set; }
        }

        // Cache a single buffer for use in GetProcessInfos().
        private static long[]? CachedBuffer;


        internal static ProcessInfo[] GetProcessInfos()
        {
            ProcessInfo[] processInfos;

            // Start with the default buffer size.
            int bufferSize = 1024; //DefaultCachedBufferSize;

            // Get the cached buffer.
            long[]? buffer = Interlocked.Exchange(ref CachedBuffer, null);

            try
            {
                while (true)
                {
                    if (buffer == null)
                    {
                        // Allocate buffer of longs since some platforms require the buffer to be 64-bit aligned.
                        buffer = new long[(bufferSize + 7) / 8];
                    }

                    uint requiredSize = 0;

                    unsafe
                    {
                        // Note that the buffer will contain pointers to itself and it needs to be pinned while it is being processed
                        // by GetProcessInfos below
                        fixed (long* bufferPtr = buffer)
                        {
                            uint status = NtQuerySystemInformation(
                                SystemProcessInformation,
                                bufferPtr,
                                (uint)(buffer.Length * sizeof(long)),
                                &requiredSize);

                            if (status != STATUS_INFO_LENGTH_MISMATCH)
                            {
                                // see definition of NT_SUCCESS(Status) in SDK
                                if ((int)status < 0)
                                {
                                    throw new InvalidOperationException(/*SR.CouldntGetProcessInfos, new Win32Exception((int)status)*/);
                                }

                                // Parse the data block to get process information
                                processInfos = GetProcessInfoEx(MemoryMarshal.AsBytes<long>(buffer));
                                break;
                            }
                        }
                    }

                    buffer = null;
                    bufferSize = GetNewBufferSize(bufferSize, (int)requiredSize);
                }
            }
            finally
            {
                // Cache the final buffer for use on the next call.
                Interlocked.Exchange(ref CachedBuffer, buffer);
            }

            return processInfos;
        }

        private static int GetNewBufferSize(int existingBufferSize, int requiredSize)
        {
            int newSize;

            if (requiredSize == 0)
            {
                //
                // On some old OS like win2000, requiredSize will not be set if the buffer
                // passed to NtQuerySystemInformation is not enough.
                //
                newSize = existingBufferSize * 2;
            }
            else
            {
                // allocating a few more kilo bytes just in case there are some new process
                // kicked in since new call to NtQuerySystemInformation
                newSize = requiredSize + 1024 * 10;
            }

            if (newSize < 0)
            {
                // In reality, we should never overflow.
                // Adding the code here just in case it happens.
                throw new OutOfMemoryException();
            }
            return newSize;
        }

        private static unsafe ProcessInfo[] GetProcessInfoEx(ReadOnlySpan<byte> data)
        {
            // Use a dictionary to avoid duplicate entries if any
            // 60 is a reasonable number for processes on a normal machine.
            Dictionary<int, ProcessInfo> processInfos = new Dictionary<int, ProcessInfo>(60);

            int processInformationOffset = 0;

            while (true)
            {
                ref readonly SYSTEM_PROCESS_INFORMATION pi = ref MemoryMarshal.AsRef<SYSTEM_PROCESS_INFORMATION>(data.Slice(processInformationOffset));

                // Process ID shouldn't overflow. OS API GetCurrentProcessID returns DWORD.
                int processInfoProcessId = pi.UniqueProcessId.ToInt32();
                //if (processIdFilter == null || processIdFilter.GetValueOrDefault() == processInfoProcessId)
                {
                    // get information for a process
                    ProcessInfo processInfo = new ProcessInfo()
                    {
                        ProcessId = processInfoProcessId,
                        SessionId = (int)pi.SessionId,
                        PoolPagedBytes = (long)pi.QuotaPagedPoolUsage,
                        PoolNonPagedBytes = (long)pi.QuotaNonPagedPoolUsage,
                        VirtualBytes = (long)pi.VirtualSize,
                        VirtualBytesPeak = (long)pi.PeakVirtualSize,
                        WorkingSetPeak = (long)pi.PeakWorkingSetSize,
                        WorkingSet = (long)pi.WorkingSetSize,
                        PageFileBytesPeak = (long)pi.PeakPagefileUsage,
                        PageFileBytes = (long)pi.PagefileUsage,
                        PrivateBytes = (long)pi.PrivatePageCount,
                        BasePriority = pi.BasePriority,
                        HandleCount = (int)pi.HandleCount,
                        NumerOfThread = (int)pi.NumberOfThreads,
                        KernelTime = (long)pi.KernelTime,
                        UserTime = (long)pi.UserTime,
                        PrivateWorkingSet = (long)pi.WorkingSetPrivateSize
                    };

                    if (pi.ImageName.Buffer == IntPtr.Zero)
                    {
                        if (processInfo.ProcessId == SystemProcessID)
                        {
                            processInfo.ProcessName = "System";
                        }
                        else if (processInfo.ProcessId == IdleProcessID)
                        {
                            processInfo.ProcessName = "Idle";
                        }
                        else
                        {
                            // for normal process without name, using the process ID.
                            processInfo.ProcessName = processInfo.ProcessId.ToString(CultureInfo.InvariantCulture);
                        }
                    }
                    else
                    {
                        string processName = GetProcessShortName(new ReadOnlySpan<char>(pi.ImageName.Buffer.ToPointer(), pi.ImageName.Length / sizeof(char)));
                        processInfo.ProcessName = processName;
                    }

                    // get the threads for current process
                    processInfos[processInfo.ProcessId] = processInfo;

                    //int threadInformationOffset = processInformationOffset + sizeof(SYSTEM_PROCESS_INFORMATION);
                    //for (int i = 0; i < pi.NumberOfThreads; i++)
                    //{
                    //    ref readonly SYSTEM_THREAD_INFORMATION ti = ref MemoryMarshal.AsRef<SYSTEM_THREAD_INFORMATION>(data.Slice(threadInformationOffset));

                    //    ThreadInfo threadInfo = new ThreadInfo
                    //    {
                    //        _processId = (int)ti.ClientId.UniqueProcess,
                    //        _threadId = (ulong)ti.ClientId.UniqueThread,
                    //        _basePriority = ti.BasePriority,
                    //        _currentPriority = ti.Priority,
                    //        _startAddress = ti.StartAddress,
                    //        _threadState = (ThreadState)ti.ThreadState,
                    //        _threadWaitReason = NtProcessManager.GetThreadWaitReason((int)ti.WaitReason),
                    //    };

                    //    processInfo._threadInfoList.Add(threadInfo);

                    //    threadInformationOffset += sizeof(SYSTEM_THREAD_INFORMATION);
                    //}
                }

                if (pi.NextEntryOffset == 0)
                {
                    break;
                }
                processInformationOffset += (int)pi.NextEntryOffset;
            }

            ProcessInfo[] temp = new ProcessInfo[processInfos.Values.Count];
            processInfos.Values.CopyTo(temp, 0);
            return temp;
        }

        internal static string GetProcessShortName(ReadOnlySpan<char> name)
        {
            if (name.IsEmpty)
            {
                return string.Empty;
            }

            int slash = -1;
            int period = -1;

            for (int i = 0; i < name.Length; i++)
            {
                if (name[i] == '\\')
                    slash = i;
                else if (name[i] == '.')
                    period = i;
            }

            if (period == -1)
                period = name.Length - 1; // set to end of string
            else
            {
                // if a period was found, then see if the extension is
                // .EXE, if so drop it, if not, then use end of string
                // (i.e. include extension in name)
                ReadOnlySpan<char> extension = name.Slice(period);

                if (extension.Equals(".exe", StringComparison.OrdinalIgnoreCase))
                    period--;                 // point to character before period
                else
                    period = name.Length - 1; // set to end of string
            }

            if (slash == -1)
                slash = 0;     // set to start of string
            else
                slash++;       // point to character next to slash

            // copy characters between period (or end of string) and
            // slash (or start of string) to make image name
            return name.Slice(slash, period - slash + 1).ToString();
        }
        static async Task Main()
        {
            await 
                Observable.Generate(
                    GetProcessInfos(),
                    _ => true,
                    _ => GetProcessInfos(),
                    pis => pis, // transform to RMM pis
                    _ => TimeSpan.FromSeconds(1)
                )
                .SelectMany(
                    pis => pis.Where(x => x.ProcessName == "notepad")
                )
                .Do(x => Console.WriteLine($"{x.ProcessName}({x.ProcessId}): TotalTime={x.TotalTime}; HandleCount={x.HandleCount}; PrivateWorkingSet={x.PrivateWorkingSet / 1024}; PrivateBytes={x.PrivateBytes};"))
                .ToTask();
        }
    }
}
