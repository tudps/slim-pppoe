# PPPoE Network Function using DPDK and the SliM state migration framework

Authors: Puneet Arora, Sooraj Mandotti, Govind Singh

The code is published to depict how to generate statelets for even a complex VNF like a PPPoE concentrator.

Note that the code cannot be built at the moment as some internally-used libraries (not relevant for the dataplane, e.g. for 
authentication etc.) are under revision and are not yet published. However, their publication (along with a Makefile) is planned
for the near future.

## Dependencies

The SliM state migration framework is available at https://github.com/nokia/SliM
