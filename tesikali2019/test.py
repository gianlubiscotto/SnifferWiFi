#!/usr/bin/env python
# coding=utf-8
import sys
import os

report = open("report.txt", "r")
macs = open("macs.txt", "r")

yes=0
no=0
tot=0

print report.readline().rstrip('\n') #titolo file

for x in macs:
	tot+=1
	print "Aggregazione da trovare"
	line1=x.rstrip('\n')
	line2=macs.next().rstrip('\n')
	print line1
	print line2

	found=0
	for y in report:
		if y.rstrip('\n') == line1:
			temp=report.next()
			if temp.rstrip('\n') == line2:
				print "trovato"
				yes+=1
				found=1
				break
				
			else:
				print "non trovato"
				break

	if not found:
		no+=1
		print "non trovato"
	report.seek(0)
	report.readline().rstrip('\n') #titolo file

print "Aggregazioni trovate:",yes,"| non trovate:",no,"| totale:",tot
yes+=0.0
percentage=yes/(yes+no)
print "Percentuale correttezza:",percentage*100,"%"
macs.close()
report.close()
