# How to run tests to benchmark scheduler performance

### Stress-ng
CPU stress testing:
```stress-ng --cpu 4 --cpu-method all --timeout 60s```
Memory stress testing:
```stress-ng --vm 2 --vm-bytes 2G --timeout 60s```
I/O stress testing:
```stress-ng --io 2 --timeout 60s```
Comprehensive testing:
```stress-ng --cpu 4 --vm 2 --io 2 --timeout 60s```

### Latencytop
#### This tests the system's responsiveness
```latencytop```

