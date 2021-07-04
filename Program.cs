using System;
using System.Diagnostics;
using System.Linq;
using System.Reactive.Linq;
using System.Reactive.Threading.Tasks;
using System.Threading.Tasks;
using static PrivateWorkingSet.Utils;

namespace PrivateWorkingSet
{
    class Program
    {
        static async Task Main()
        {
            await 
                Observable.Generate(
                    (
                        sample_previous: new ProcessInfo[0], 
                        timestamp_previous: 0L, 
                        sample_last: GetProcessInfos(), 
                        timestamp_last: Stopwatch.GetTimestamp()
                    ),
                    _ => true,
                    x => 
                    (
                        sample_previous: x.sample_last, 
                        timestamp_previous: x.timestamp_last, 
                        sample_last: GetProcessInfos(), 
                        timestamp_last: Stopwatch.GetTimestamp()
                    ),
                    samples => {
                        var total_processor_time = (samples.timestamp_last - samples.timestamp_previous) * Environment.ProcessorCount;

                        return
                            samples.sample_last.Join(
                                samples.sample_previous,
                                x => x.ProcessId,
                                x => x.ProcessId,
                                (sample_last, sample_previous) => (
                                    name: sample_last.ProcessName,
                                    pid: sample_last.ProcessId,
                                    pws: sample_last.PrivateWorkingSet,
                                    cpu: (100.0 * (sample_last.TotalTime - sample_previous.TotalTime)) / total_processor_time
                                )
                            )
                            .ToList();
                    },
                    _ => TimeSpan.FromSeconds(1)
                )
                .Skip(1)
                .Do(xs =>
                {
                    xs.Where(x => x.cpu >= 1 && x.pid != 0)
                    .ToList()
                    .ForEach(x => Console.WriteLine($"{x.name}({x.pid}): cpu={Math.Round(x.cpu, 2)} %; pws={x.pws / 1024} kB;"));

                    Console.WriteLine($"TOTAL: {Math.Min(100, Math.Round(xs.Where(x => x.pid != 0).Sum(xs => xs.cpu), 2))} %");
                    Console.WriteLine();
                })
                .ToTask();
        }
    }
}
