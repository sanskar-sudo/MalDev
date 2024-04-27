
![Logo](https://th.bing.com/th/id/R.258386bc8e9497ee1d6477d8b2ef20e1?rik=VbSv5Xnhy4tLpQ&riu=http%3a%2f%2fres.publicdomainfiles.com%2fpdf_view%2f89%2f13942894813440.png&ehk=W8cAawH%2f%2bi6z%2fNDKcUzitCaf%2b6oH2Wq9Qn0iGPbK%2byM%3d&risl=&pid=ImgRaw&r=0)


# Project Title

Maliglitch is a malware written in c++ that attempts to hide from debugging, execute shellcode, and establish persistence on the system.



## Features

- Detection of Debugging: The UnderTheMicroscope() function checks whether the program is being debugged by examining the BeingDebugged field of the Process Environment Block (PEB) structure.

- Shellcode Execution: The code defines a shellcode array and allocates memory to execute it. The shellcode is copied into the allocated memory and then executed by creating a new thread.

- Persistence Mechanism Installation: The InstallPersistence() function adds the current executable to the Windows registry startup programs, ensuring it runs every time the system boots.

- Console Window Hiding: The console window is hidden using FreeConsole().
