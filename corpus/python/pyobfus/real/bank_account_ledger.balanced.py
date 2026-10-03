# pyobfus:generated format=1 edition=community
# Tool: pyobfus 0.5.30 - https://github.com/zhurong2020/pyobfus
# Source: bank_account_ledger.py
# DO NOT EDIT - generated output
from decimal import Decimal
I3 = Decimal('-100.00')
I1 = Decimal('2.50')

class I2(Exception):
    pass

class I0:
    I9 = 1000

    def __init__(I13, I10, I5='0'):
        I13.owner = I10
        I13.balance = Decimal(I5)
        I13.number = I0.I9
        I0.I9 += 1
        I13.ledger = []

    def I6(I13, I4):
        I4 = Decimal(I4)
        if I4 <= 0:
            raise ValueError('deposit must be positive')
        I13.balance += I4
        I13.ledger.append(('deposit', I4))
        return I13.balance

    def I18(I13, I4):
        I4 = Decimal(I4)
        I11 = I13.balance - I4
        if I11 < I3:
            raise I2('%s: %s' % (I13.owner, I11))
        if I11 < 0:
            I11 -= I1
            I13.ledger.append(('fee', I1))
        I13.balance = I11
        I13.ledger.append(('withdraw', I4))
        return I13.balance

    def I15(I13):
        I8 = ['Account %d (%s)' % (I13.number, I13.owner)]
        I12 = Decimal(0)
        for I7, I4 in I13.ledger:
            I12 += I4 if I7 == 'deposit' else -I4
            I8.append('%-8s %10s %10s' % (I7, I4, I12))
        return '\n'.join(I8)

def I17(I14, I16, I4):
    try:
        I14.I18(I4)
    except I2:
        return False
    else:
        I16.I6(I4)
        return True
    finally:
        I14.ledger.append(('transfer', Decimal(0)))