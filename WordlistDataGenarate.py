#!/usr/bin/python3
print("\n\n\n\nAbra o arquivo 'datas.txt' que foi criado no diretrio atual,\ncontendo 127224 linhas e 1.181.124 bytes(1,2Mb)\n\n\n\n")

def nascimento():
    texto = open("datas.txt", 'w')
    ano = 1959
    while ano <= 2016:
        ano += 1
        mes = 0
        while mes < 12:
            mes += 1
            if mes >= 10:
                dia = 0
                while dia < 31:
                    dia += 1
                    if dia > 9:
                        texto.write(str("%s-%s-%s\n" % (dia, mes, ano)))
                        texto.write(str("%s/%s/%s\n" % (dia, mes, ano)))
                        texto.write(str("%s%s%s\n" % (dia, mes, ano)))
                    if dia <= 9:
                        texto.write(str("0%s-%s-%s\n" %(dia, mes, ano)))
                        texto.write(str("0%s/%s/%s\n" %(dia, mes, ano)))
                        texto.write(str("0%s%s%s\n" %(dia, mes, ano)))
            if mes <= 9:
                dia = 0
                while dia < 31:
                    dia += 1
                    if dia > 9:
                        texto.write(str("%s-0%s-%s\n" % (dia, mes, ano)))
                        texto.write(str("%s/0%s/%s\n" % (dia, mes, ano)))
                        texto.write(str("%s0%s%s\n" % (dia, mes, ano)))
                    if dia <= 9:
                        texto.write(str("0%s-0%s-%s\n" % (dia, mes, ano)))
                        texto.write(str("0%s/0%s/%s\n" % (dia, mes, ano)))
                        texto.write(str("0%s0%s%s\n" % (dia, mes, ano)))
    ano = 59
    while ano < 99:
        ano += 1
        mes = 0
        while mes < 12:
            mes += 1
            if mes >= 10:
                dia = 0
                while dia < 31:
                    dia += 1
                    if dia > 9:
                        texto.write(str("%s-%s-%s\n" % (dia, mes, ano)))
                        texto.write(str("%s/%s/%s\n" % (dia, mes, ano)))
                        texto.write(str("%s%s%s\n" % (dia, mes, ano)))
                    if dia <= 9:
                        texto.write(str("0%s-0%s-%s\n" % (dia, mes, ano)))
                        texto.write(str("0%s/%s/%s\n" %(dia, mes, ano)))
                        texto.write(str("0%s%s%s\n" %(dia, mes, ano)))
            if mes <= 9:
                dia = 0
                while dia < 31:
                    dia += 1
                    if dia > 9:
                        texto.write(str("%s-0%s-%s\n" % (dia, mes, ano)))
                        texto.write(str("%s/0%s/%s\n" % (dia, mes, ano)))
                        texto.write(str("%s0%s%s\n" % (dia, mes, ano)))
                    if dia <= 9:
                        texto.write(str("0%s-0%s-%s\n" % (dia, mes, ano)))
                        texto.write(str("0%s/0%s/%s\n" % (dia, mes, ano)))
                        texto.write(str("0%s0%s%s\n" % (dia, mes, ano)))
    ano = 00
    while ano < 9:
        ano += 1
        mes = 0
        while mes < 12:
            mes += 1
            if mes >= 9:
                dia = 0
                while dia < 31:
                    dia += 1
                    if dia > 9:
                        texto.write(str("%s-%s-0%s\n" % (dia, mes, ano)))
                        texto.write(str("%s/%s/0%s\n" % (dia, mes, ano)))
                        texto.write(str("%s%s0%s\n" % (dia, mes, ano)))
                    if dia <= 9:
                        texto.write(str("0%s-%s-0%s\n" % (dia, mes, ano)))
                        texto.write(str("0%s/%s/0%s\n" %(dia, mes, ano)))
                        texto.write(str("0%s%s0%s\n" %(dia, mes, ano)))
            if mes <= 9:
                dia = 0
                while dia < 31:
                    dia += 1
                    if dia > 9:
                        texto.write(str("%s-0%s-0%s\n" % (dia, mes, ano)))
                        texto.write(str("%s/0%s/0%s\n" % (dia, mes, ano)))
                        texto.write(str("%s0%s0%s\n" % (dia, mes, ano)))
                    if dia <= 9:
                        texto.write(str("0%s-0%s-0%s\n" % (dia, mes, ano)))
                        texto.write(str("0%s/0%s/0%s\n" % (dia, mes, ano)))
                        texto.write(str("0%s0%s0%s\n" % (dia, mes, ano)))        
    texto.close()
nascimento()
