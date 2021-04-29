# DNS-Server-Pipe
Computer Networking — HW 1

Evyatar Weiss		
Hananel Mandeleyl	


Instructions:
Run command: make
Run command: ./nsclient "DNS Server ip Address"
intpu:
  "nsclient> "
input from client - hostname
  "nsclient> bakara.eng.tau.ac.il"
output -
  "132.66.48.12"
  "nsclient> fsd342**"
  "ERROR: BAD NAME"
  "nsclient> zooot.tau.ac.il"
  "ERROR: NONEXISTENT"


Code Structure:

1. We first define data structures to hold the various packet sections.
2. Then, we connect to the DNS server address provided by the user via the command line arguments.
3. We sets up the required infrastracture to later communicate with the DNS server via UDP via UDP protocol.
4. Now, we read the desired hostname from the command line.
5. Using the hostname we formulate as quesry for the DNS server:
	a. We first allocate a buffer to contain the query and its future answer.
	b. Then, we initialize all the required structures and place them sequentially in the buffer.
	c. Finally, we pass the buffer as the query to the DNS server.
5. Next, we wait for the server to respond.
6. Once we receive a responce we write it to the original buffer, overwriting the existing query (query's contant returns in the response).
7. We then analyze the buffer, and map the response's data structures to its relevant sections.
8. After obtaining all the necessary information and storing it in the corresponding data structures, we finally fill in the struct hostent, return a pointer to it, and print the address.

Notes:
1. We has a few issues with endianness, where bits would be read wrong from memory. We solved the issues manually as <endians.h> was not supported on Windows.
2. We used WireShark for testing and successfuly verified our outputs. We've gained a deep understanding of the packets' content and were later able to pinpoint the critical information and distinguish it from the metadata.
