

![Logo](https://th.bing.com/th/id/R.439ceba5823e9662c3a567f3ab267e89?rik=l%2fCHtrcTEmyhOQ&riu=http%3a%2f%2fdownload.bitsdujour.com%2fsoftware%2ficon%2fwise-anti-malware.png&ehk=VeJVkGEqaO7EYfuZ7xYgZs5EbL8Vj9VJShcvM8LE%2b%2b8%3d&risl=&pid=ImgRaw&r=0)



# MalDev

Maliglitch is a malware written in c++ that attempts to hide from debugging, execute shellcode, and establish persistence on the system.



## Features

- Detection of Debugging: The UnderTheMicroscope() function checks whether the program is being debugged by examining the BeingDebugged field of the Process Environment Block (PEB) structure.

- Shellcode Execution: The code defines a shellcode array and allocates memory to execute it. The shellcode is copied into the allocated memory and then executed by creating a new thread.

- Persistence Mechanism Installation: The InstallPersistence() function adds the current executable to the Windows registry startup programs, ensuring it runs every time the system boots.

- Console Window Hiding: The console window is hidden using FreeConsole().
