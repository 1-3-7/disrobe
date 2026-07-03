A=print
C='hello from disrobe'
D=42
B={}
class E:
	label:str;values:list[int]
	def __init__(A,label,values):A.label=label;A.values=values
	def filtered(A,minimum):return[A for A in A.values if A>=minimum]
	def summary(D):B=D.filtered(0);C=sum(B);A=len(B);return{'total':C,'count':A,'mean':C//A if A else 0}
def F(text):A=[chr(ord(A)+1)for A in text];return''.join(A)
def G(key):
	A=key
	if A not in B:B[A]=len(F(A))
	return B[A]
def H(items):
	A=[]
	for C in items:
		B=G(C)
		if B>D:A.append(B)
	return A
if __name__=='__main__':I=E(C,[10,50,30,70,20]);A(I.summary());A(H(['alpha','beta','gamma','delta']))
# Created by pyminifier (https://github.com/liftoff/pyminifier)
