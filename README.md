# jvm-blocking-monitor

**This project is no longer maintained. Use https://github.com/kawamuray/jbm instead**

jvm-blocking-monitor is an agent that monitors JVM processes from the kernel using eBPF. It detects when an application thread is blocking for an extended period of time and generates a backtrace from the kernel to userspace. It then reports this information, providing valuable insights into blocking issues within your JVM applications.

# Usage

```sh
git clone https://github.com/kawamuray/jvm-blocking-monitor.git

# Build async-profiler
git submodule update --init
cd async-profiler
git submodule update --init
make -j8

# Example usage for detecting "block" behavior defined as a thread stopped over a second but less than a minute
./jvm-blocking-monitor.py -p TARGET_JVM_PID --min-block-time 1000000 --max-block-time 60000000
```

## License

JBM is licensed under the [MIT License](https://opensource.org/licenses/MIT). You are free to use, modify, and distribute this software. See the `LICENSE` file for more information.
