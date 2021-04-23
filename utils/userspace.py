import time
to_read = file("/sys/kernel/debug/reutos/mydata", "rb")
outputfile = file("/home/areuter/Desktop/rowhammerfilez/results/run32/results.txt", "ab")
buff_full = file("/sys/kernel/debug/reutos/buff_full", "wb+")

datum_count = 0

def canRead():
	#Opening file again in here because illegal seek, cant read
	buff_fullx = file("/sys/kernel/debug/reutos/buff_full", "rwb")
	res = buff_fullx.read().strip() is "1"
	buff_fullx.close()
	return res


while True:
	if canRead():
		print("Buff is full, reading..." + str(datum_count))
		to_read = file("/sys/kernel/debug/reutos/mydata", "rb")
		data = to_read.read()
		to_read.close()
		print(len(data))
		outputfile.write(data)
		outputfile.flush()
		buff_full.write("0")
		buff_full.flush()
		print(canRead())
		if canRead():
			print("SEEMS WRONG")
			break;
		datum_count += 1
	else:
		print("Buff not full")
	time.sleep(0.1)

outputfile.close()
to_read.close()
buff_full.close()
