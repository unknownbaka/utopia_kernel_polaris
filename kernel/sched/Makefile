ifdef CONFIG_FUNCTION_TRACER
CFLAGS_REMOVE_clock.o = $(CC_FLAGS_FTRACE)
endif

# These files are disabled because they produce non-interesting flaky coverage
# that is not a function of syscall inputs. E.g. involuntary context switches.
KCOV_INSTRUMENT := n

ifneq ($(CONFIG_SCHED_OMIT_FRAME_POINTER),y)
# According to Alan Modra <alan@linuxcare.com.au>, the -fno-omit-frame-pointer is
# needed for x86 only.  Why this used to be enabled for all architectures is beyond
# me.  I suspect most platforms don't need this, but until we know that for sure
# I turn this off for IA-64 only.  Andreas Schwab says it's also needed on m68k
# to get a correct value for the wait-channel (WCHAN in ps). --davidm
CFLAGS_core.o := $(PROFILING) -fno-omit-frame-pointer
endif

obj-y += core.o loadavg.o clock.o cputime.o
obj-y += idle_task.o fair.o rt.o deadline.o stop_task.o
obj-y += wait.o swait.o completion.o idle.o
obj-$(CONFIG_SMP) += cpupri.o cpudeadline.o energy.o sched_avg.o
obj-$(CONFIG_SCHED_WALT) += walt.o 
obj-$(CONFIG_SCHED_AUTOGROUP) += auto_group.o
obj-$(CONFIG_SCHEDSTATS) += stats.o
obj-$(CONFIG_SCHED_DEBUG) += debug.o
obj-$(CONFIG_SCHED_TUNE) += tune.o
obj-$(CONFIG_SCHED_TUNE_DUMMY) += tune_dummy.o
obj-$(CONFIG_CGROUP_CPUACCT) += cpuacct.o
obj-$(CONFIG_CPU_FREQ) += cpufreq.o
obj-$(CONFIG_CPU_FREQ_GOV_SCHEDUTIL) += cpufreq_schedutil.o
obj-$(CONFIG_SCHED_CORE_CTL) += core_ctl.o
obj-$(CONFIG_PACKAGE_RUNTIME_INFO) += runtime.o
obj-$(CONFIG_PSI) += psi.o
