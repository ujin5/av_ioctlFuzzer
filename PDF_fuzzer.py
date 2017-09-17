# -*- coding:utf-8 -*-
# Module : pdf_fuzzer.py

#------------------------------------------------------------
# 설명 : OLE 구조를 가지는 hwp, doc, ppt, xls 확장자를 가진 파일을 뮤테이션시킨다.
#------------------------------------------------------------
import os
from pyZZUF import *
from random import choice
import shutil

class PDF_FUZZ:

    def __init__(self, seed_dir, out_dir, filename):
        self.SEED_DIR = seed_dir
        self.OUT_DIR = out_dir
        self.FILENAME = filename
        self.new_data = ""
        self.fp = open(self.SEED_DIR + self.FILENAME, "rb")

    #------------------------------------------------------------
    # 함수명 : Mutation
    # 설  명 : pdf 파일을 뮤테이션시킨 후 파일에 쓴다.
    #------------------------------------------------------------
    def Mutation(self):

        data = self.fp.read()
        
        self.new_data = self.fuzz_pdf(data)
        
        # 뮤테이션된 값을 파일에 쓰기
        if self.new_data != None:
            fp = open(self.OUT_DIR + self.FILENAME, "wb")
            fp.write(self.new_data)

    #------------------------------------------------------------
    # 함수명 : fuzz_pdf
    # 설  명 : pdf 파일을 뮤테이션시킨다.
    # 인자값 : data : 뮤테이션시킬 데이터
    # 반환값 : rdata : 뮤테이션시킨 데이터
    #------------------------------------------------------------
    def fuzz_pdf(self, data):

        signature = data[0:4]

        rdata = ""
        rdata += signature
        rdata += pyZZUF(data[4:]).mutate().tostring()
        
        return rdata
