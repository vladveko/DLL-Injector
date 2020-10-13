#include <Windows.h>
#include <iostream>

int main()
{
	SetConsoleTitleA("TextOutApp");
	char text[] = "Hello World!";
	for (;;) {
		std::cout << text;
		std::cout << "\n";
		Sleep(1000);
	}
}
