Correctly implemented:
- NULL scan
- FIN scan
- Xmas scan
- Usernames and passwords sent in-the-clear via HTTP Basic Authentication, FTP
- Nikto scan
- Someone scanning for Remote Desktop Protocol (RDP) protocol

Not implemented:
- Unsure if IMAP username password works as intended since I am using lstrip on "3 LOGIN" which could differ on different IMAP login requests


Identify anyone with whom you have collaborated or discussed the assignment.
Pani Bhengsri, Keene Lenevant

Say approximately how many hours you have spent completing the assignment.
3h

Are the heuristics used in this assignment to determine incidents "even that good"?
No they are not perfect.


If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?
Add more checks to be more thorough and ensure more edge cases will be covered.