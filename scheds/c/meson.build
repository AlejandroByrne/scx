c_scheds = ['scx_simple', 'scx_qmap', 'scx_central', 'scx_pair', 'scx_flatcg', 'scx_userland', 'scx_nest', 'scx_test_us', 'scx_test_ks', 'scx_fifo', 'scx_ringbuf_us', 'scx_data_plot_ks', 'scx_data_plot_us', 'scx_ks', 'scx_ml_ks']

foreach sched: c_scheds
  thread_dep = dependency('threads')
  bpf_o = gen_bpf_o.process(sched + '.bpf.c', extra_args: bpf_includes)
  bpf_skel = gen_bpf_skel.process(bpf_o)
  executable(sched, [bpf_skel, sched + '.c'],
             include_directories: [user_c_includes],
             dependencies: [kernel_dep, libbpf_dep, thread_dep],
             install: true)
endforeach
