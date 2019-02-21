# Secure-Kademlia
Based on Kademlia Protocol
Check design doc to understand the implementation.
Kademlia is handled seperately by a thread with priority Queue.
All incoming UDP requests are handled by a thread and pushed to To Queue from which one more thread reads and creates a session.
Session is used for maintaining the keys through which messages are encoded and decoded.
