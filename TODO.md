# TODO LIST:
* ### finish the CPU frequency tracking and graphing
    * have to get the CPU tracer to work at the same time as the scheduler
* ### ensure proper struct_task movement throughout the scheduling lifetime
* ### record the % of time spent running for the user-space program
    * every time it startis running, start the timer
    * when it stops, end the timer
    * add that sum to 'total_running_time' and take ratio with 'total_time'