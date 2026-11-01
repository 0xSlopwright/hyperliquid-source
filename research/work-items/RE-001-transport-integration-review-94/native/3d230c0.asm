
artifacts/node/94/hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000003d230c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1284d40>:
 3d230c0:	55                                              	push   rbp
 3d230c1:	41 57                                           	push   r15
 3d230c3:	41 56                                           	push   r14
 3d230c5:	41 55                                           	push   r13
 3d230c7:	41 54                                           	push   r12
 3d230c9:	53                                              	push   rbx
 3d230ca:	50                                              	push   rax
 3d230cb:	48 8b 46 20                                     	mov    rax,QWORD PTR [rsi+0x20]
 3d230cf:	48 85 c0                                        	test   rax,rax
 3d230d2:	0f 84 06 01 00 00                               	je     3d231de <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1284c22>
 3d230d8:	48 89 3c 24                                     	mov    QWORD PTR [rsp],rdi
 3d230dc:	48 8b 7e 28                                     	mov    rdi,QWORD PTR [rsi+0x28]
 3d230e0:	44 0f b7 5e 18                                  	movzx  r11d,WORD PTR [rsi+0x18]
 3d230e5:	48 8b 16                                        	mov    rdx,QWORD PTR [rsi]
 3d230e8:	4c 8b 46 08                                     	mov    r8,QWORD PTR [rsi+0x8]
 3d230ec:	4c 8b 4e 30                                     	mov    r9,QWORD PTR [rsi+0x30]
 3d230f0:	4c 8b 56 38                                     	mov    r10,QWORD PTR [rsi+0x38]
 3d230f4:	66 66 66 2e 0f 1f 84 00 00 00 00 00             	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
 3d23100:	66 45 85 db                                     	test   r11w,r11w
 3d23104:	75 32                                           	jne    3d23138 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1284cc8>
 3d23106:	66 2e 0f 1f 84 00 00 00 00 00                   	cs nop WORD PTR [rax+rax*1+0x0]
 3d23110:	66 41 0f 6f 00                                  	movdqa xmm0,XMMWORD PTR [r8]
 3d23115:	66 44 0f d7 d8                                  	pmovmskb r11d,xmm0
 3d2311a:	48 81 c2 80 fd ff ff                            	add    rdx,0xfffffffffffffd80
 3d23121:	49 83 c0 10                                     	add    r8,0x10
 3d23125:	41 81 fb ff ff 00 00                            	cmp    r11d,0xffff
 3d2312c:	74 e2                                           	je     3d23110 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1284cf0>
 3d2312e:	41 f7 d3                                        	not    r11d
 3d23131:	4c 89 46 08                                     	mov    QWORD PTR [rsi+0x8],r8
 3d23135:	48 89 16                                        	mov    QWORD PTR [rsi],rdx
 3d23138:	41 8d 5b ff                                     	lea    ebx,[r11-0x1]
 3d2313c:	f3 45 0f bc f3                                  	tzcnt  r14d,r11d
 3d23141:	44 21 db                                        	and    ebx,r11d
 3d23144:	41 89 db                                        	mov    r11d,ebx
 3d23147:	66 89 5e 18                                     	mov    WORD PTR [rsi+0x18],bx
 3d2314b:	49 f7 de                                        	neg    r14
 3d2314e:	4f 8d 3c b6                                     	lea    r15,[r14+r14*4]
 3d23152:	48 ff c8                                        	dec    rax
 3d23155:	48 89 46 20                                     	mov    QWORD PTR [rsi+0x20],rax
 3d23159:	4a 8b 5c fa d8                                  	mov    rbx,QWORD PTR [rdx+r15*8-0x28]
 3d2315e:	4e 8b 64 fa e0                                  	mov    r12,QWORD PTR [rdx+r15*8-0x20]
 3d23163:	45 31 f6                                        	xor    r14d,r14d
 3d23166:	4d 87 74 24 10                                  	xchg   QWORD PTR [r12+0x10],r14
 3d2316b:	4e 8b 64 fa e8                                  	mov    r12,QWORD PTR [rdx+r15*8-0x18]
 3d23170:	45 31 ed                                        	xor    r13d,r13d
 3d23173:	4d 87 6c 24 10                                  	xchg   QWORD PTR [r12+0x10],r13
 3d23178:	4e 8b 64 fa f0                                  	mov    r12,QWORD PTR [rdx+r15*8-0x10]
 3d2317d:	45 31 ff                                        	xor    r15d,r15d
 3d23180:	4d 87 7c 24 10                                  	xchg   QWORD PTR [r12+0x10],r15
 3d23185:	4c 8b 27                                        	mov    r12,QWORD PTR [rdi]
 3d23188:	4d 01 f4                                        	add    r12,r14
 3d2318b:	0f 82 e0 00 00 00                               	jb     3d23271 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1284b8f>
 3d23191:	4c 89 27                                        	mov    QWORD PTR [rdi],r12
 3d23194:	4d 8b 21                                        	mov    r12,QWORD PTR [r9]
 3d23197:	4d 01 ec                                        	add    r12,r13
 3d2319a:	0f 82 de 00 00 00                               	jb     3d2327e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1284b82>
 3d231a0:	4d 89 21                                        	mov    QWORD PTR [r9],r12
 3d231a3:	4d 8b 22                                        	mov    r12,QWORD PTR [r10]
 3d231a6:	4d 01 fc                                        	add    r12,r15
 3d231a9:	0f 82 b5 00 00 00                               	jb     3d23264 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1284b9c>
 3d231af:	4d 89 22                                        	mov    QWORD PTR [r10],r12
 3d231b2:	4d 85 f6                                        	test   r14,r14
 3d231b5:	40 0f 94 c5                                     	sete   bpl
 3d231b9:	49 89 dc                                        	mov    r12,rbx
 3d231bc:	49 c1 ec 30                                     	shr    r12,0x30
 3d231c0:	41 80 fc 02                                     	cmp    r12b,0x2
 3d231c4:	0f 94 c1                                        	sete   cl
 3d231c7:	40 08 e9                                        	or     cl,bpl
 3d231ca:	74 17                                           	je     3d231e3 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1284c1d>
 3d231cc:	48 85 c0                                        	test   rax,rax
 3d231cf:	0f 85 2b ff ff ff                               	jne    3d23100 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1284d00>
 3d231d5:	41 b4 02                                        	mov    r12b,0x2
 3d231d8:	48 8b 3c 24                                     	mov    rdi,QWORD PTR [rsp]
 3d231dc:	eb 70                                           	jmp    3d2324e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1284bb2>
 3d231de:	41 b4 02                                        	mov    r12b,0x2
 3d231e1:	eb 6b                                           	jmp    3d2324e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1284bb2>
 3d231e3:	66 49 0f 6e c5                                  	movq   xmm0,r13
 3d231e8:	f3 0f 7e 0d 90 0c 4e fc                         	movq   xmm1,QWORD PTR [rip+0xfffffffffc4e0c90]        # 203e80 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x4da3f80>
 3d231f0:	66 0f 62 c1                                     	punpckldq xmm0,xmm1
 3d231f4:	66 0f 28 15 a4 fc 4d fc                         	movapd xmm2,XMMWORD PTR [rip+0xfffffffffc4dfca4]        # 202ea0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x4da4f60>
 3d231fc:	66 0f 5c c2                                     	subpd  xmm0,xmm2
 3d23200:	66 0f 28 d8                                     	movapd xmm3,xmm0
 3d23204:	66 0f 15 d8                                     	unpckhpd xmm3,xmm0
 3d23208:	f2 0f 58 d8                                     	addsd  xmm3,xmm0
 3d2320c:	66 49 0f 6e c6                                  	movq   xmm0,r14
 3d23211:	66 0f 62 c1                                     	punpckldq xmm0,xmm1
 3d23215:	66 0f 5c c2                                     	subpd  xmm0,xmm2
 3d23219:	66 0f 28 c8                                     	movapd xmm1,xmm0
 3d2321d:	66 0f 15 c8                                     	unpckhpd xmm1,xmm0
 3d23221:	f2 0f 58 c8                                     	addsd  xmm1,xmm0
 3d23225:	f2 0f 5e d9                                     	divsd  xmm3,xmm1
 3d23229:	48 89 d8                                        	mov    rax,rbx
 3d2322c:	48 c1 e8 38                                     	shr    rax,0x38
 3d23230:	48 8b 3c 24                                     	mov    rdi,QWORD PTR [rsp]
 3d23234:	89 1f                                           	mov    DWORD PTR [rdi],ebx
 3d23236:	48 c1 eb 20                                     	shr    rbx,0x20
 3d2323a:	66 89 5f 04                                     	mov    WORD PTR [rdi+0x4],bx
 3d2323e:	88 47 07                                        	mov    BYTE PTR [rdi+0x7],al
 3d23241:	4c 89 77 08                                     	mov    QWORD PTR [rdi+0x8],r14
 3d23245:	4c 89 7f 10                                     	mov    QWORD PTR [rdi+0x10],r15
 3d23249:	f2 0f 11 5f 18                                  	movsd  QWORD PTR [rdi+0x18],xmm3
 3d2324e:	44 88 67 06                                     	mov    BYTE PTR [rdi+0x6],r12b
 3d23252:	48 89 f8                                        	mov    rax,rdi
 3d23255:	48 83 c4 08                                     	add    rsp,0x8
 3d23259:	5b                                              	pop    rbx
 3d2325a:	41 5c                                           	pop    r12
 3d2325c:	41 5d                                           	pop    r13
 3d2325e:	41 5e                                           	pop    r14
 3d23260:	41 5f                                           	pop    r15
 3d23262:	5d                                              	pop    rbp
 3d23263:	c3                                              	ret
 3d23264:	48 8d 3d 85 67 9f 01                            	lea    rdi,[rip+0x19f6785]        # 57199f0 <__register_atfork@plt+0xb87b0>
 3d2326b:	ff 15 a7 ae a4 01                               	call   QWORD PTR [rip+0x1a4aea7]        # 576e118 <__register_atfork@plt+0x10ced8>
 3d23271:	48 8d 3d 48 67 9f 01                            	lea    rdi,[rip+0x19f6748]        # 57199c0 <__register_atfork@plt+0xb8780>
 3d23278:	ff 15 9a ae a4 01                               	call   QWORD PTR [rip+0x1a4ae9a]        # 576e118 <__register_atfork@plt+0x10ced8>
 3d2327e:	48 8d 3d 53 67 9f 01                            	lea    rdi,[rip+0x19f6753]        # 57199d8 <__register_atfork@plt+0xb8798>
 3d23285:	ff 15 8d ae a4 01                               	call   QWORD PTR [rip+0x1a4ae8d]        # 576e118 <__register_atfork@plt+0x10ced8>
