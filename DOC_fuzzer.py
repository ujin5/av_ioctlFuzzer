# -*- coding:utf-8 -*-
# Module : DOC_fuzzer.py

#------------------------------------------------------------
# 설명 : Document 파일을 뮤테이션시킨다.
#------------------------------------------------------------
from Mut_Rada import *
import os
from pyZZUF import *
from random import choice
import shutil

class DOC_FUZZ:

    def __init__(self, seed_dir, out_dir, filename):
        self.SEED_DIR = seed_dir
        self.OUT_DIR = out_dir
        self.FILENAME = filename
        self.new_data = ""
        self.fp = open(self.SEED_DIR + self.FILENAME, "rb")

    #------------------------------------------------------------
    # 함수명 : Mutation
    # 설  명 : DOC 파일을 뮤테이션시킨 후 파일에 쓴다.
    #------------------------------------------------------------
    def Mutation(self):

        data = self.fp.read()
        
        # 확장자 확인하기
        ext = self.FILENAME.split(".")[1]
        #print "file extension : %s" % ext

        # ole 구조 가지는 파일 확장자별로 맞춤형 mutation하기
        if ext == "hwp" or ext == "xls":
            self.new_data = self.ole_fuzz_without_sub_header(data)
        elif ext == "doc" or ext == "ppt":
            self.new_data = self.ole_fuzz_with_sub_header(data)
        # ole 구조가 아닌 doc 확장자별로 맞춤형 mutation하기
        elif ext == "pdf":
            self.new_data = self.pdf_fuzz(data)
        elif ext == "chm":
            self.new_data = self.chm_fuzz(data)
        elif ext == "rtf":
            self.new_data = self.rtf_fuzz(data)
        else:
            self.new_data = None
        
        # mutation된 값을 파일에 쓰기
        if self.new_data != None:
            fp = open(self.OUT_DIR + self.FILENAME, "wb")
            fp.write(self.new_data)

    #------------------------------------------------------------
    # 함수명 : ole_fuzz_without_sub_header
    # 설  명 : V3에서 sub_header를 검사하지 않는 OLE 구조를 가지는 파일을 뮤테이션시킨다.
    # 인자값 : data : 뮤테이션시킬 데이터
    # 반환값 : rdata : 뮤테이션시킨 데이터
    #------------------------------------------------------------
    def ole_fuzz_without_sub_header(self, data):

        signature = data[0:8]

        rdata = ""
        rdata += signature
        rdata += radamsa(data[8:]).mutate().tostring()
        
        return rdata

    #------------------------------------------------------------
    # 함수명 : ole_fuzz_with_sub_header
    # 설  명 : V3에서 sub_header를 검사하는 OLE 구조 가지는 파일을 뮤테이션시킨다.
    # 인자값 : data : 뮤테이션시킬 데이터
    # 반환값 : rdata : 뮤테이션시킨 데이터
    #------------------------------------------------------------
    def ole_fuzz_with_sub_header(self, data):

        signature = data[0:8]

        rdata = ""
        rdata += signature
        rdata += radamsa(data[8:512]).mutate().tostring()

        sub_signature = data[512:516]
        rdata = rdata[:512]
        rdata += sub_signature
        rdata += radamsa(data[516:]).mutate().tostring()

        return rdata

    #------------------------------------------------------------
    # 함수명 : pdf_fuzz
    # 설  명 : pdf 파일을 뮤테이션시킨다.
    # 인자값 : data : 뮤테이션시킬 데이터
    # 반환값 : rdata : 뮤테이션시킨 데이터
    #------------------------------------------------------------
    def pdf_fuzz(self, data):

        signature = data[0:4]

        rdata = ""
        rdata += signature
        rdata += radamsa(data[4:]).mutate().tostring()
        
        return rdata

    #------------------------------------------------------------
    # 함수명 : chm_fuzz
    # 설  명 : chm 파일을 뮤테이션시킨다.
    # 인자값 : data : 뮤테이션시킬 데이터
    # 반환값 : rdata : 뮤테이션시킨 데이터
    #------------------------------------------------------------
    def chm_fuzz(self, data):

        signature = data[0:4]

        rdata = ""
        rdata += signature
        rdata += radamsa(data[4:]).mutate().tostring()
        
        return rdata

    #------------------------------------------------------------
    # 함수명 : rtf_fuzz
    # 설  명 : rtf 파일을 뮤테이션시킨다.
    # 인자값 : data : 뮤테이션시킬 데이터
    # 반환값 : rdata : 뮤테이션시킨 데이터
    #------------------------------------------------------------
    def rtf_fuzz(self, data):

        signature = data[0:6]

        rdata = ""
        rdata += signature
        rdata += radamsa(data[6:]).mutate().tostring()
        
        return rdata
