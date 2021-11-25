# -*- coding: utf-8 -*-

from androguard.core.analysis.analysis import ClassAnalysis
from lib import abstractopcodes
import numpy as np
import math
import Levenshtein
import logging
import sys

logger = logging.getLogger("similarity_score")
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
logger.addHandler(ch)

def average(list):
    if list:
        return sum(list) / len(list)
    else:
        return 0

def jaccard_similarity(list1, list2):
    s1 = set(list1)
    s2 = set(list2)
    if len(s1.union(s2)) == 0:
        return 1
    return float(len(s1.intersection(s2)) / len(s1.union(s2)))

def score_fields_similarity(class1_analysis, class2_analysis):
    field_score = 0
    
    fields_class1 = class1_analysis.get_fields()
    enc_fields_class1 = class1_analysis.get_vm_class().get_fields()
    
    fields_class2 = class2_analysis.get_fields()
    enc_fields_class2 = class2_analysis.get_vm_class().get_fields()


    if not fields_class1 and not fields_class2:
        field_score = 5/100 + 5/100 + 3/100 + 3/100
        return field_score
    elif not fields_class1 or not fields_class2:
        field_score = 0
        return 0
    else:
        descriptors1 = [field.get_descriptor() for field in enc_fields_class1]
        descriptors2 = [field.get_descriptor() for field in enc_fields_class2]
        field_score += jaccard_similarity(descriptors1, descriptors2) * 5/100
        
        access_flags1 = [field.get_access_flags_string() for field in enc_fields_class1]
        access_flags2 = [field.get_access_flags_string() for field in enc_fields_class2]
        field_score += jaccard_similarity(access_flags1, access_flags2) * 5/100
        
        
        fields1_xref_read = [len(field.get_xref_read()) for field in fields_class1]
        fields2_xref_read  = [len(field.get_xref_read()) for field in fields_class2]
        average1_xref_read = average(fields1_xref_read)
        average2_xref_read = average(fields2_xref_read)
        tmp_average = abs(average1_xref_read - average2_xref_read)
        if average1_xref_read == average2_xref_read:
            field_score += 3/100
        elif tmp_average < 1:
            field_score += 3/100
        else:
            field_score += 3/100 * 0.9/abs(average1_xref_read - average2_xref_read)
        
        fields1_xref_write = [len(field.get_xref_write()) for field in fields_class1]
        fields2_xref_write  = [len(field.get_xref_write()) for field in fields_class2]
        average1_xref_write = average(fields1_xref_write)
        average2_xref_write = average(fields2_xref_write)
        tmp_average = abs(average1_xref_write - average2_xref_write)
        if average1_xref_write == average2_xref_write:
            field_score += 3/100
        elif tmp_average < 1:
            field_score += 3/100
        else:
            field_score += 3/100 * 0.9/abs(average1_xref_write - average2_xref_write)
    logger.debug("Similarity score for field is: {}".format(field_score))
    return field_score


def score_class_similarity(class1_analysis, class2_analysis):
    class_score = 0
    
    # TODO chose 1 of the 2
    # 1 method 
    # if class1_analysis.get_nb_methods() == class2_analysis.get_nb_methods():
    #     class_score += 8/100
    # else:
    #     class_score += 8/100 * 0.9/abs(class1_analysis.get_nb_methods() - class2_analysis.get_nb_methods())
    # 2 method  
    if len(class1_analysis.get_vm_class().get_methods()) == len(class2_analysis.get_vm_class().get_methods()):
        class_score += 8/100
    else:
        class_score += 8/100 * 0.9/abs(len(class1_analysis.get_vm_class().get_methods()) - len(class2_analysis.get_vm_class().get_methods()))
    if len(class1_analysis.get_vm_class().get_fields()) == len(class2_analysis.get_vm_class().get_fields()):
        class_score += 6/100
    else:
        class_score += 6/100 * 0.9/abs(len(class1_analysis.get_vm_class().get_fields()) - len(class2_analysis.get_vm_class().get_fields()))
    
    xref_from1 = class1_analysis.get_xref_from()
    xref_from2 = class2_analysis.get_xref_from()
    if not xref_from1 and xref_from2:
        class_score += 5/100 * 0.9/(len(xref_from2))
    elif not xref_from2 and xref_from1:
        class_score += 5/100 * 0.9/(len(xref_from1))
    elif not xref_from1 and not xref_from2:
        class_score += 5/100 + 5/100
    else:
        if len(xref_from1) == len(xref_from2):
            class_score += 5/100
            ref1_kinds = [str(ref_kind) for caller, refs in xref_from1.items() for ref_kind, ref_method, ref_offset in refs]
            ref2_kinds = [str(ref_kind) for caller, refs in xref_from2.items() for ref_kind, ref_method, ref_offset in refs]
            class_score += 5/100 * jaccard_similarity(ref1_kinds, ref2_kinds)
        else:
            class_score += 5/100 * 0.9/abs(len(xref_from1) - len(xref_from2))
            ref1_kinds = [str(ref_kind) for caller, refs in xref_from1.items() for ref_kind, ref_method, ref_offset in refs]
            ref2_kinds = [str(ref_kind) for caller, refs in xref_from2.items() for ref_kind, ref_method, ref_offset in refs]
            class_score += 5/100 * jaccard_similarity(ref1_kinds, ref2_kinds)
           
    xref_to1 = class1_analysis.get_xref_to()
    xref_to2 = class2_analysis.get_xref_to()
    if not xref_to1 and xref_to2:
        class_score += 5/100 * 0.9/(len(xref_to2))
    elif not xref_to2 and xref_to1:
        class_score += 5/100 * 0.9/(len(xref_to1))
    elif not xref_to1 and not xref_to2:
        class_score += 5/100 + 5/100
    else:
        if len(xref_to1) == len(xref_to2):
            class_score += 5/100
            ref1_kinds = [str(ref_kind) for caller, refs in xref_to1.items() for ref_kind, ref_method, ref_offset in refs]
            ref2_kinds = [str(ref_kind) for caller, refs in xref_to2.items() for ref_kind, ref_method, ref_offset in refs]
            class_score += 5/100 * jaccard_similarity(ref1_kinds, ref2_kinds)
        else:
            class_score += 5/100 * 0.9/abs(len(xref_to1) - len(xref_to2))
            ref1_kinds = [str(ref_kind) for caller, refs in xref_to1.items() for ref_kind, ref_method, ref_offset in refs]
            ref2_kinds = [str(ref_kind) for caller, refs in xref_to2.items() for ref_kind, ref_method, ref_offset in refs]
            class_score += 5/100 * jaccard_similarity(ref1_kinds, ref2_kinds)
    
    nb_implementations1 = len(class1_analysis.implements)
    nb_implementations2 = len(class2_analysis.implements)
    
    if nb_implementations1 == nb_implementations2:
        class_score += 4/100
    else:
        class_score += 4/100 * 0.9/abs(nb_implementations1 - nb_implementations2)
    logger.debug("Similarity score for class is: {}".format(class_score))
    return class_score


def score_method_similarity(class1_analysis, class2_analysis):
    method_score = 0
    
    methods1 = class1_analysis.get_methods()
    methods2 = class2_analysis.get_methods()
    
    descriptors1 = [method.descriptor for method in methods1]
    descriptors2 = [method.descriptor for method in methods2]
    method_score += 8/100 * jaccard_similarity(descriptors1, descriptors2)
    
    access_flags1 = [method.access for method in methods1]
    access_flags2 = [method.access for method in methods2]
    method_score += 7/100 * jaccard_similarity(access_flags1, access_flags2)
    
    
    xrefs1_from = [method.get_xref_from() for method in methods1]
    xrefs1_from_access = []
    xrefs1_from_len = []
    for xrefs_from in xrefs1_from:
        if xrefs_from:
            for xref in xrefs_from:
                if isinstance(xref[0], ClassAnalysis):
                    xrefs1_from_access.append(xref[1].get_access_flags_string())
            xrefs1_from_len.append(len(xrefs_from))
    xrefs2_from = [method.get_xref_from() for method in methods2]
    xrefs2_from_access = []
    xrefs2_from_len = []
    for xrefs_from in xrefs2_from:
        if xrefs_from:
            for xref in xrefs_from:
                if isinstance(xref[0], ClassAnalysis):
                    xrefs2_from_access.append(xref[1].get_access_flags_string())
            xrefs2_from_len.append(len(xrefs_from))
    
    method_score += 4/100 * jaccard_similarity(xrefs1_from_access, xrefs2_from_access)
    average1_xref_from = average(xrefs1_from_len)
    average2_xref_from = average(xrefs2_from_len)
    tmp_average = abs(average1_xref_from - average2_xref_from)
    if average1_xref_from == average2_xref_from:
        method_score += 4/100
    elif tmp_average < 1:
        method_score += 4/100
    else:
        method_score += 4/100 * 0.9/abs(average1_xref_from - average2_xref_from)
    
    
    xrefs1_to = [method.get_xref_to() for method in methods1]
    xrefs1_to_access = []
    xrefs1_to_len = []
    for xrefs_to in xrefs1_to:
        if xrefs_to:
            for xref in xrefs_to:
                if isinstance(xref[0], ClassAnalysis):
                    xrefs1_to_access.append(xref[1].get_access_flags_string())
            xrefs1_to_len.append(len(xrefs_to))
    xrefs2_to = [method.get_xref_to() for method in methods2]
    xrefs2_to_access = []
    xrefs2_to_len = []
    for xrefs_to in xrefs2_to:
        if xrefs_to:
            for xref in xrefs_to:
                if isinstance(xref[0], ClassAnalysis):
                    xrefs2_to_access.append(xref[1].get_access_flags_string())
            xrefs2_to_len.append(len(xrefs_to))
    method_score += 4/100 * jaccard_similarity(xrefs1_to_access, xrefs2_to_access)
    average1_xref_to = average(xrefs1_to_len)
    average2_xref_to = average(xrefs2_to_len)
    tmp_average = abs(average1_xref_to - average2_xref_to)
    if average1_xref_to == average2_xref_to:
        method_score += 4/100
    elif tmp_average < 1:
        method_score += 4/100
    else:
        method_score += 4/100 * 0.9/abs(average1_xref_to - average2_xref_to)
    logger.debug("Similarity score for method is: {}".format(method_score))
    return method_score


def score_code_similarity(class1_analysis, class2_analysis):
    code_score = 0
    
    enc_methods1 = class1_analysis.get_vm_class().get_methods()
    enc_methods2 = class2_analysis.get_vm_class().get_methods()
    
    code_seq1 = get_ord_code_seq(enc_methods1)
    code_seq2 = get_ord_code_seq(enc_methods2)
    
    distance = Levenshtein.distance(bin(code_seq1), bin(code_seq2))
    logger.debug("Levenshtein distance is: {}".format(distance))
    if distance == 0:
        code_score = 15/100
    else:
        code_score = 15/100 * 0.8 * (math.sqrt(distance))/(distance)
    logger.debug("Similarity score for code is: {}".format(code_score))
    return code_score

def get_ord_code_seq(enc_methods):
    
    tmp_dic = {}
    for i in enc_methods:
        tmp_og_opcodes = []
        tmp_abs_opcodes = []
        if i.get_code() is not None:
            tmp_og_opcodes = [y.get_op_value() for y in i.get_code().get_bc().get_instructions()]
            tmp_abs_opcodes = [abstractopcodes.get_abstract_family_value(opcode) for opcode in tmp_og_opcodes]
            tmp_xor = 0
            for opcode in tmp_abs_opcodes:
                tmp_xor = tmp_xor ^ opcode
            sig = len(tmp_abs_opcodes) << 4 | tmp_xor
            tmp_dic[sig] = tmp_abs_opcodes
    tmp_sigs = [key for key in tmp_dic]
    tmp_sigs.sort()
    tmp_code_seq = [opcode for i in tmp_sigs for opcode in tmp_dic[i]]
    final_seq = 0
    for opcode in tmp_code_seq: 
        final_seq = final_seq << 4 | opcode
    return final_seq
def calculate_similarity_score(class1_analysis, class2_analysis, log_level=logging.WARNING):
    logger.setLevel(log_level)
    similarity_score = 0
    
    similarity_score += score_fields_similarity(class1_analysis, class2_analysis)
    similarity_score += score_class_similarity(class1_analysis, class2_analysis)
    similarity_score += score_method_similarity(class1_analysis, class2_analysis)
    similarity_score += score_code_similarity(class1_analysis, class2_analysis)
    
    # rounding up indentical clases
    if (1 - similarity_score) < 0.0000001:
        return 1.0
    return similarity_score