#include <stdlib.h>
#include <windows.h>

int main()
{
    // Hide Console Window
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    
    // Start ArpCut.exe in a detached process
    system("start \"\" ArpCut");
    return 0;
}