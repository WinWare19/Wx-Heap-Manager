# Wx-Heap-Manager
Custom implementation of a Heap Manager

Wx-Heap Manager is a custom implementation of a heap manager. It supports all the features of the default Windows heap manager, except for the walking mechanism. The manager provides coalescing of free blocks and fragmentation of large blocks, and multiple heaps can be created. Large allocations (larger than PAGE_SIZE) are supported. Internally, each wx-heap can consist of multiple non‑contiguous segments and can grow as needed.
 
