---
title: "Return-to-libc Attack"
teaching: 10
exercises: 30
questions:
- "What is the return-to-libc attack?"
- "Why is it dangerous?"
- "What can you do to prevent this attack on your system?"
objectives:
- "Follow instructions to successfully demonstrate the return-to-libc attack."
---

## Return-to-libc Attack
The learning objective of this lab is for students to gain the first-hand experience on an interesting variant of
buffer-overflow attack; this attack can bypass an existing protection scheme currently implemented in major
Linux operating systems. A common way to exploit a buffer-overflow vulnerability is to overflow the buffer
with a malicious shellcode, and then cause the vulnerable program to jump to the shellcode that is stored in
the stack. To prevent these types of attacks, some operating systems allow programs to make their stacks
non-executable; therefore, jumping to the shellcode will cause the program to fail.

Unfortunately, the above protection scheme is not fool-proof; there exists a variant of buffer-overflow
attack called the Return-to-libc attack, which does not need an executable stack; it does not even use shell-
code. Instead, it causes the vulnerable program to jump to some existing code, such as the system()
function in the libc library, which is already loaded into a process’s memory space.

In this lab, students are given a program with a buffer-overflow vulnerability; their task is to develop
a Return-to-libc attack to exploit the vulnerability and finally to gain the root privilege. In addition to the
attacks, students will be guided to walk through some protection schemes that have been implemented in
Ubuntu to counter against the buffer-overflow attacks. This lab covers the following topics:
* Buffer overflow vulnerability and attack
* Stack layout in a function invocation
* Non-executable stack
* Address randomization
* The libc functions

### Demonstration

#### Turning off Countermeasures
You can execute the lab tasks using our pre-built Ubuntu virtual machines. Ubuntu and other Linux
distributions have implemented several security mechanisms to make the buffer-overflow attack difficult. To simplify
our attacks, we need to disable them first.

**Address Space Randomization.** Ubuntu and several other Linux-based systems uses address space ran-
domization [?] to randomize the starting address of heap and stack. This makes guessing the exact addresses
difficult; guessing addresses is one of the critical steps of buffer-overflow attacks. In this lab, we disable this
feature using the following command:

```bash
$ sudo sysctl -w kernel.randomize_va_space=0
```
