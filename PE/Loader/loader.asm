[bits 32]
[org 0x12345678]

start:

OEP:      dd 0xFEEDC0DE ; eax+0
SecStart: dd 0xFEEDDA7A ; eax+4
SecSize:  dd 0xFEEDDA7A ; eax+8

times (0x200 - ($-start)) db 0xcc


code:
  call $+5
  pop eax
  and ax, 0xf000

  push esi
  push ecx

  mov esi, [eax+4]
  mov ecx, [eax+8]
  decrypt:
    xor byte [esi+ecx-1], 0x55
    loop decrypt
  
  pop ecx
  pop esi

  jmp [eax]
  
