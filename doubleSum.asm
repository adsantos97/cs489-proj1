segment .text
global DoubleSum		        ; declare a global symbol for our function
				            ; and declare the 'function' symbol global
DoubleSum:
	.arg_0	equ 8			; declare some local constants to reference our
	.arg_4	equ 12		            ; stack frame in IDA Pro fashion
	.var_4	equ -4

	push ebp			; save the previous frame pointer
	mov ebp, esp			; setup a new frame for this function
	sub esp, 4			; and create 4 bytes of local variable space
	mov byte [ebp+.var_4], 0	; initialize local variable to 0
	movzx eax, byte [ebp+.var_4]	; load local variable into eax
	add eax, [ebp+.arg_0]		; add the first argument to the local var
	add eax, [ebp+.arg_4]		; add the second argument to the total
        shl eax, 1                      ; multiply by 2
	mov esp, ebp			; cleanup our stack frame
	pop ebp				; restore the pointer to the previous frame
	ret					; return from this function
