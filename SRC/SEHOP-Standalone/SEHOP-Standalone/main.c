/*
* This is an example modified from the C++ Example in the 
* Microsfot Documentation
* 
* https://learn.microsoft.com/en-us/cpp/cpp/try-except-statement?view=msvc-170
*/
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>

#include <windows.h> 
#include <excpt.h>

#define INT
#define UNSAFE

int filter(unsigned int code, struct _EXCEPTION_POINTERS* ep)
{
#ifdef INT
    __asm int 3;
#endif // INT

    printf("In Filter Function.\n");
    if (code == EXCEPTION_ACCESS_VIOLATION)
    {
        printf("Caught Access Violoation Exception as expected.\n");
        return EXCEPTION_EXECUTE_HANDLER;
    }
    else
    {
        printf("Did not catch Access Violoation Exception as expected. Unexpected Exception caught.\n");
        return EXCEPTION_CONTINUE_SEARCH;
    };
#ifdef INT
    __asm int 3;
#endif // INT
}



int main(void) {
    char str_buff[20];      // Allocate space on the stack to overflow
    int* p = 0x00000000;   // pointer to NULL


#ifdef INT
    __asm int 3;
#endif // INT


#ifdef UNSAFE
    printf("Enter User Input: ");
    scanf("%s", str_buff);
#endif

    printf("Address of Filter Function: 0x%p\n", filter);
    printf("STRBUFF: %s\n", str_buff);

#ifdef INT
    __asm int 3;
#endif // INT

    // SEH Handling in the function
    __try {
        printf("Generating Exception\n");
        *p = 13;    // causes an access violation exception;
    }
    __except (filter(GetExceptionCode(), GetExceptionInformation())) {
        // termination code
        printf("Exception Raised as Expected\n");
    }
}