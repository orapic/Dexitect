# -*- coding: utf-8 -*-
import jinja2
import collections
import androguard.misc
import xmldiff
import os
import argparse
import subprocess
import androguard.core.analysis
import datetime
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import axml
from xmldiff import main, formatting
import shutil
import zipfile
import glob
from androguard.core.analysis.analysis import ExternalMethod
from androguard.core.analysis.analysis import ClassAnalysis
from fnvhash import fnv1a_32
from lib import abstractopcodes
from lib import similarityscorer
from simhash import Simhash, SimhashIndex

DROIDBANNER = '''
               **                 **              
                 *    *******    *                
                *******************               
             .***********************             
            *****  *************  *****           
           *****************************          
          *******************************     

  _____            _ _            _   
 |  __ \          (_) |          | |  
 | |  | | _____  ___| |_ ___  ___| |_ 
 | |  | |/ _ \ \/ / | __/ _ \/ __| __|
 | |__| |  __/>  <| | ||  __/ (__| |_ 
 |_____/ \___/_/\_\_|\__\___|\___|\__|
                                      
'''

SIMHASH_RESULTS_FILE = "simhash_results.txt"
MAIN_RESULTS_FILE = "outputs.txt"




def create_folder(path, message):
    try:
        os.mkdir(path)
    except Exception as e:
        pass
    else:
        if message:
            print(message)

def create_directory_recursive(directories_path):
    # directories_path must be a string with /
    cnt = 0
    for i in range(0, len(directories_path.split("/"))-1):
        if cnt == (len(directories_path.split("/"))-1) and "." in directories_path.split("/")[-1]:
            return
        create_folder("/".join(directories_path.split("/")[0:i+1]), "Creating folder "+ "/".join(directories_path.split("/")[0:i+1]))
        cnt+=1


def print_and_save(message, file_output):
    temp = ""
    if isinstance(message, list):
        for i in message:
            if not temp:
                temp = i
            else:
                temp = temp + ", " + i
        message = temp
    with open(file_output, "a") as file:
        file.write("\n")
        file.write(message)
    print(message)

class apk_comparison(object):
    
    def __init__(self, apk1_path, apk2_path, config):
        self.apk1_path = apk1_path
        self.apk2_path = apk2_path
        self.obfuscated = config["obfuscated"]
        self.threshold = config["threshold"]
        self.hamming_distance = config["hamming_distance"]
        self.comparison_result_folder = "outputs/" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        create_folder(self.comparison_result_folder, "Results will be saved at: {}".format(self.comparison_result_folder))
        self.config = config
        self.results_file_path = self.comparison_result_folder + "/" + MAIN_RESULTS_FILE
        self.simhash_results_file_path = self.comparison_result_folder + "/" + SIMHASH_RESULTS_FILE
        
        start_time = datetime.datetime.now()
        self.apk1_handle, self.d1, self.dx1 = androguard.misc.AnalyzeAPK(self.apk1_path)
        finish_time = datetime.datetime.now()
        self.apk1_analysis_time = finish_time - start_time
        print_and_save("Analysis of {} done in: {}".format(self.apk1_path, str(self.apk1_analysis_time)), self.results_file_path)
        
        start_time = datetime.datetime.now()
        self.apk2_handle, self.d2, self.dx2 = androguard.misc.AnalyzeAPK(self.apk2_path)
        finish_time = datetime.datetime.now()
        self.apk2_analysis_time = finish_time - start_time
        print_and_save("Analysis of {} done in: {}".format(self.apk2_path, str(self.apk2_analysis_time)), self.results_file_path)
        
        self.classes_added = set()
        self.classes_deleted = set()
        self.classes_bulk = collections.defaultdict(set)
        self.classes_accute = collections.defaultdict(set)
        self.classes_empty = set()
        self.classes_similar = {}
        
        self.apk1_notfound_classes = {}
        self.apk2_notfound_classes = {}
        
        self.nb_classes_apk1 = 0
        self.nb_classes_apk2 = 0
        
        self.dupsearch_time = 0
        self.total_time = 0
    
    def compare(self):
        start_total_time = datetime.datetime.now()
        self.bulk_comparison()
        self.accute_comparison()
        print_and_save("", self.results_file_path)
        print_and_save("* Classes Deleted ({})*".format(len(self.classes_deleted)), self.results_file_path)
        for deleted_class in sorted(self.classes_deleted):
            with open(self.comparison_result_folder + "/deleted_classes.txt", "a") as f:
                f.write("{}\n".format(deleted_class))
        print_and_save("* Classes Added ({})*".format(len(self.classes_added)), self.results_file_path)
        for added_class in sorted(self.classes_added):
            with open(self.comparison_result_folder + "/added_classes.txt", "a") as f:
                f.write("{}\n".format(added_class))
        print_and_save("* Empty Classes ({})*".format(len(self.classes_empty)), self.results_file_path)
        for empty_class in sorted(self.classes_empty):
            with open(self.comparison_result_folder + "/empty_classes.txt", "a") as f:
                f.write("{}\n".format(empty_class))
        finish_total_time = datetime.datetime.now()
        self.total_time = finish_total_time - start_total_time
        print("Total time diffing done in : {}".format(self.total_time))
        #self.generate_HTML_Report()
        self.generate_HTML_report_jinja()
       
    
    def bulk_comparison(self):

        apk1_simhashes = []
        start_time = datetime.datetime.now()
        if self.config["excluded_packages"]:
            #apk1_simhashes = [(class1.name, self.calc_signature_class(class1)) for class1 in self.dx1.get_internal_classes() if not self.check_if_excluded(class1.name, self.config["excluded_packages"])]
            for class1 in self.dx1.get_internal_classes():
                if not self.check_if_excluded(class1.name, self.config["excluded_packages"]) and not self.check_if_empty_class(class1):
                    apk1_simhashes.append((class1.name, self.calc_signature_class(class1)))
                    self.apk1_notfound_classes[class1.name] = 0
                elif not self.check_if_excluded(class1.name, self.config["excluded_packages"]) and self.check_if_empty_class(class1):
                    self.classes_empty.add(class1.name)
        else:
            #apk1_simhashes = [(class1.name, self.calc_signature_class(class1)) for class1 in self.dx1.get_internal_classes()]
            for class1 in self.dx1.get_internal_classes():
                if not self.check_if_empty_class(class1):
                    apk1_simhashes.append((class1.name, self.calc_signature_class(class1)))
                    self.apk1_notfound_classes[class1.name] = 0
        finish_time = datetime.datetime.now()
        simhash_time = finish_time - start_time
        print_and_save("Simhashing of the {} done in: {}".format(self.apk1_path, str(simhash_time)), self.results_file_path)
        
        index1 = SimhashIndex(apk1_simhashes,f=128, k=self.config["hamming_distance"])
        print_and_save("Comparison made with a hamming distance of: " + str(self.config["hamming_distance"]), self.results_file_path)
        
        start_time = datetime.datetime.now()
        apk2_simhashes = []
        if self.config["excluded_packages"]:
            #apk2_simhashes = [(class2.name, self.calc_signature_class(class2)) for class2 in self.dx2.get_internal_classes() if not self.check_if_excluded(class2.name, self.config["excluded_packages"])]
            for class2 in self.dx2.get_internal_classes():
                if not self.check_if_excluded(class2.name, self.config["excluded_packages"]) and not self.check_if_empty_class(class2):
                    apk2_simhashes.append((class2.name, self.calc_signature_class(class2)))
                    self.apk2_notfound_classes[class2.name] = 0          
        else:
            #apk2_simhashes = [(class2.name, self.calc_signature_class(class2)) for class2 in self.dx2.get_internal_classes()]
            for class2 in self.dx2.get_internal_classes():
                if not self.check_if_empty_class(class2):
                    apk2_simhashes.append((class2.name, self.calc_signature_class(class2)))
                    self.apk2_notfound_classes[class2.name] = 0      
        finish_time = datetime.datetime.now()
        simhash_time = finish_time - start_time
        index2 = SimhashIndex(apk2_simhashes,f=128, k=self.config["hamming_distance"])
        print_and_save("Simhashing of the {} done in: {}".format(self.apk2_path, str(simhash_time)), self.results_file_path)
        
        start_time = datetime.datetime.now()
        count_not_present = 0
        no_dups = 0
        number_dups = 0
        possible_deletions = []
        possible_additions = []
        class_candidates = 0
        with open(self.simhash_results_file_path, "a") as file:
            for simhash in apk1_simhashes:
                dups = index2.get_near_dups(simhash[1])
                file.write(simhash[0])
                if dups:
                    class_candidates += 1
                    self.classes_bulk[simhash[0]] = set(dups)
                    if simhash[0] not in dups and not self.config["obfuscated"]:
                        count_not_present += 1
                        file.write(" (not found in duplicates)")
                    file.write(" -> [")
                    for dup in dups:
                        file.write(dup + " ")
                        self.apk2_notfound_classes.pop(dup, None)
                    file.write("]")
                    number_dups += len(dups)
                    self.apk1_notfound_classes.pop(simhash[0], None)
                else:
                    no_dups += 1
                    file.write(" -> NO NEAR DUPLICATES!")
                    possible_deletions.append(simhash[0])
                file.write("\n")
        
        possible_additions = [key for key in self.apk2_notfound_classes]
        finish_time = datetime.datetime.now()
        
        self.dupsearch_time = finish_time - start_time
        print_and_save("Duplicate search done in:" + str(self.dupsearch_time), self.results_file_path)
        self.nb_classes_apk1 = len(apk1_simhashes)
        self.nb_classes_apk2 = len(apk2_simhashes)
        print_and_save("Number of classes analysed in apk1: " + str(len(apk1_simhashes)), self.results_file_path)
        print_and_save("Number of classes analysed in apk2: " + str(len(apk2_simhashes)), self.results_file_path)
        print_and_save("Number of classes which do not have near duplicates: " + str(no_dups), self.results_file_path)
        if not self.config["obfuscated"]:
            print_and_save("Class which name is not present in the candidates list: " +str(count_not_present), self.results_file_path)
        average_dups = number_dups / len(self.classes_bulk)
        print_and_save("Average number of duplicates for classes with candidates: " + str(average_dups), self.results_file_path)
        self.classes_deleted = set(possible_deletions)
        self.classes_added = set(possible_additions)

    
    def get_possible_additions(self, index_simhash, apk_simhashes, obfuscated):
        possible_additions = []
        for simhash in apk_simhashes:
            dups = index_simhash.get_near_dups(simhash[1])
            if not dups:
                possible_additions.append(simhash[0])
        return possible_additions
    
    def check_if_empty_class(self, class_analysis):
        if class_analysis.get_nb_methods() == 0 and len(class_analysis.get_fields()) == 0:
            return True
        return False
    
    def check_if_excluded(self, class_name, excluded_packages):
        found = False
        for excluded in excluded_packages:
            if class_name.find(excluded, 1) != -1:
                found = True
        if found:
                return True
        else:
            return False
    
    def extract_features_field(self, field_analysis):
        field_features = []
        field_encoded = field_analysis.get_field()
        field_features.append(field_encoded.get_descriptor())
        field_features.append(field_encoded.get_access_flags_string())
        field_features.append(str(len(field_analysis.get_xref_read())))
        field_features.append(str(len(field_analysis.get_xref_write())))
        try:
            field_features.append(str(field_encoded.get_init_value().get_value()))
        except:
            pass
        return field_features

    def calc_simhash_fields_ft(self, input_class):
        fields_ft_simhash = ""
        fields = input_class.get_fields()
        input_features = []
        for field in fields:
            input_features.extend(self.extract_features_field(field))
        # todo
        return Simhash(input_features, f=32, hashfunc=fnv1a_32)
    
    def extract_features_class(self, class_analysis):
        class_features = []

        class_features.extend(class_analysis.get_vm_class().get_access_flags_string())
        
        class_features.append(str(len(class_analysis.get_vm_class().get_methods())))
        if len(class_analysis.get_vm_class().get_fields()) != 0:
            for i in range(3):
                class_features.append("has_fields")
        else:
            class_features.append("no_fields")
        class_features.append(str(len(class_analysis.get_vm_class().get_fields())))
        xref_from = class_analysis.get_xref_from()
        if xref_from:
            class_features.append(str(len(xref_from)))
            ref_kinds = [str(ref_kind) for caller, refs in xref_from.items() for ref_kind, ref_method, ref_offset in refs]
            class_features.extend(ref_kinds)
        xref_to = class_analysis.get_xref_to()
        if xref_to:
            class_features.append(str(len(xref_to)))
            ref_kinds_hashes = [str(ref_kind) for caller, refs in xref_to.items() for ref_kind, ref_method, ref_offset in refs]
            class_features.extend(ref_kinds_hashes)
        class_features.append(str(len(class_analysis.implements)))
        if len(class_analysis.implements) != 0:
            for i in range(2):
                class_features.append("implements")
        if class_analysis.extends != "Ljava/lang/Object;":
            for i in range(2):
                class_features.append("extends")
        return class_features
    
    def calc_simhash_class_ft(self, input_class):
        class_features = self.extract_features_class(input_class)
        return Simhash(class_features, f=32, hashfunc=fnv1a_32)
    
    def extract_features_method(self, method_analysis):
        method_features = []
        method_features.append(method_analysis.descriptor)
        method_features.append(method_analysis.access)
        xrefs_from = method_analysis.get_xref_from()
        if xrefs_from:
            for xref in xrefs_from:
                if isinstance(xref[0], ClassAnalysis):
                    method_features.append(xref[1].get_access_flags_string())
            method_features.append(str(len(xrefs_from)))
        xrefs_to = method_analysis.get_xref_to()
        if xrefs_to:
            for xref in xrefs_to:
                if isinstance(xref[0], ClassAnalysis):
                    method_features.append(xref[1].get_access_flags_string())
            method_features.append(str(len(xrefs_from)))
        return method_features
    
    def calc_simhash_methods_ft(self, input_class):
        method_features = []
        class_methods = input_class.get_methods()
        for method in class_methods:
            method_features.extend(self.extract_features_method(method))
        return Simhash(method_features, f=32, hashfunc=fnv1a_32)
    
    def extract_features_code(self, method_analysis):
        code_features = []
        if method_analysis.is_external() is False:
            encoded_method = method_analysis.get_method()
            d_code = encoded_method.get_code()
            if d_code is not None:
                code_features = [abstractopcodes.get_abstract_family_string(y.get_op_value()) for y in d_code.get_bc().get_instructions()]
        return code_features
    
    def calc_simhash_code(self, input_class):
        code_features = []
        class_methods = input_class.get_methods()
        # TODO
        for method in class_methods:
            tmp = self.extract_features_code(method)
            if tmp:
                code_features.extend(self.extract_features_code(method))
        return Simhash(code_features, f=32, hashfunc=fnv1a_32)
    
    def calc_signature_class(self, input_class):
        class_features_simhash = self.calc_simhash_class_ft(input_class)
        methods_features_simhash = self.calc_simhash_methods_ft(input_class)
        fields_features_simhash = self.calc_simhash_fields_ft(input_class)    
        code_simhash = self.calc_simhash_code(input_class)
        # Concatenate simhash calculated before
        input_to_concat = [class_features_simhash, methods_features_simhash, fields_features_simhash, code_simhash]
        return Simhash(input_to_concat, f=128, concatenate=True)
    
    
    def find_nearest_neighbours(self, class_signature, config):
        
        # TODO
        return 1
    
    def get_abstract_opcodes(self, method_analysis):
        original_opcodes = []
        abstract_opcodes = []
        if method_analysis.is_external() is False:
            encoded_method = method_analysis.get_method()
            d_code = encoded_method.get_code()
            if d_code is not None:
                original_opcodes = [y.get_op_value() for y in d_code.get_bc().get_instructions()]
        abstract_opcodes = abstractopcodes.get_abstract_family_string(original_opcodes)
        return abstract_opcodes
    
    def accute_comparison(self):
        print_and_save("", self.results_file_path)
        print_and_save("*** Comparison reuslts ***", self.results_file_path)
        print_and_save("* Similar classes ({})*".format(len(self.classes_bulk)), self.results_file_path)
        print_and_save("FORMAT : Class 1 in apk1 -> Candidates with highest similarity score in apk2", self.results_file_path)
        #print("Bulk dict len {}".format(len(self.classes_bulk)))
        cnt = 0
        for k, v in self.classes_bulk.items():
            #print(cnt)
            if v:
                #print("Class to be analysed {}".format(k))
                self.classes_accute[k] = collections.defaultdict(float)
                for candidate_name in v:
                    if candidate_name is not None:
                        similarity_score = similarityscorer.calculate_similarity_score(self.dx1.get_class_analysis(k), self.dx2.get_class_analysis(candidate_name) )
                        self.classes_accute[k][candidate_name] = similarity_score
            cnt += 1
        #TODO
        for k, v in self.classes_accute.items():
            max_score = 0
            max_score_names = []
            candidates = False
            if v:
                for candidate_name, candidate_score in v.items():
                    if candidate_name is not None:
                        candidates = True
                        if candidate_score == max_score:
                            max_score_names.append(candidate_name)
                        elif candidate_score > max_score:
                            max_score_names = []
                            max_score = candidate_score
                            max_score_names.append(candidate_name)
                    else:
                        print_and_save("{} has no near candidates".format(k))
                if candidates:
                    print_and_save("{} -> {} | {}".format(k, " ".join(max_score_names),  str(max_score)), self.results_file_path)
                    self.classes_similar[k] = {'score' : max_score, 'candidates' : set(max_score_names)}

    
    def highest_similarity_neighbour(self, class1, class1_neighbours, threshold):
        current_highest = []
        cnt = 0
        for i in class1_neighbours:
            similarity_score = self.calc_similarity_score(class1, i)
            if similarity_score >= threshold:
                if current_highest:
                        if similarity_score > current_highest[1]:
                            current_highest = [i, similarity_score]
                else:
                    current_highest = [i, similarity_score]
            cnt += 1
        if current_highest:
            return current_highest[0], current_highest[1]
        else:
            return None, None
    
    def generate_HTML_report_jinja(self):
        create_folder(self.comparison_result_folder + "/HTML_report", "")
        
        nb_similar_classes = len(self.classes_bulk)
        nb_added_classes = len(self.classes_added)
        nb_deleted_classes = len(self.classes_deleted)
        nb_empty_classes = len(self.classes_empty)
        
        index_html = jinja2.Environment(
            loader = jinja2.FileSystemLoader('./')
            ).get_template('res/index_template.html').render(
                nb_similar_classes = nb_similar_classes,
                nb_added_classes = nb_added_classes,
                nb_deleted_classes = nb_deleted_classes,
                nb_empty_classes = nb_empty_classes,
                apk1_path = self.apk1_path,
                apk2_path = self.apk2_path,
                dupsearch_time = self.dupsearch_time,
                total_time = self.total_time,
                nb_classes_apk1 = self.nb_classes_apk1,
                nb_classes_apk2 = self.nb_classes_apk2
                )
        with open(self.comparison_result_folder + "/HTML_report/index.html",'w') as f:
            f.write(index_html)        
        
        similar_html = jinja2.Environment(
            loader = jinja2.FileSystemLoader('./')
            ).get_template('res/similar_template.html').render(
                nb_similar_classes = nb_similar_classes,
                nb_added_classes = nb_added_classes,
                nb_deleted_classes = nb_deleted_classes,
                nb_empty_classes = nb_empty_classes,
                classes_similar = self.classes_similar
                )
        with open(self.comparison_result_folder + "/HTML_report/similar_classes.html",'w') as f:
            f.write(similar_html)

        added_html = jinja2.Environment(
            loader = jinja2.FileSystemLoader('./')
            ).get_template('/res/added_template.html').render(
                nb_similar_classes = nb_similar_classes,
                nb_added_classes = nb_added_classes,
                nb_deleted_classes = nb_deleted_classes,
                nb_empty_classes = nb_empty_classes,
                classes_added = sorted(self.classes_added)
                )
        with open(self.comparison_result_folder + "/HTML_report/added_classes.html",'w') as f:
            f.write(added_html)
        
        deleted_html = jinja2.Environment(
            loader = jinja2.FileSystemLoader('./')
            ).get_template('/res/deleted_template.html').render(
                nb_similar_classes = nb_similar_classes,
                nb_added_classes = nb_added_classes,
                nb_deleted_classes = nb_deleted_classes,
                nb_empty_classes = nb_empty_classes,
                classes_deleted = self.classes_deleted
                )
        with open(self.comparison_result_folder + "/HTML_report/deleted_classes.html",'w') as f:
            f.write(deleted_html)
            
        empty_html = jinja2.Environment(
            loader = jinja2.FileSystemLoader('./')
            ).get_template('/res/empty_template.html').render(
                nb_similar_classes = nb_similar_classes,
                nb_added_classes = nb_added_classes,
                nb_deleted_classes = nb_deleted_classes,
                nb_empty_classes = nb_empty_classes,
                classes_empty = sorted(self.classes_empty)
                )
        with open(self.comparison_result_folder + "/HTML_report/empty_classes.html",'w') as f:
            f.write(empty_html)            
        pass
    def generate_HTML_Report(self):
        create_folder(self.comparison_result_folder + "/res", "")
        
        html_text = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        html_text += '<html xmlns="http://www.w3.org/1999/xhtml">\n'
        html_text += '\n'
        html_text += '<head>\n'
        html_text += '<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>\n'
        html_text += '<title> Droidiffv2 Report </title>\n' 
        html_text += '</head>\n'
 
        html_text += '<frameset cols="290,10%">\n'
        html_text += '<frame src="res/nav.html" name="nav" frameborder="0"/>\n' 
        html_text += '<frame src="res/summary.html" name="contents" frameborder="1"/>\n'
        html_text += '<noframes/>\n'
        html_text += '</frameset>\n'
        html_text += '\n'
        html_text += '</html>\n'
        with open(self.comparison_result_folder + "/index.html","w") as f:
            f.write(html_text)
        
        index_html = '<html><head>\n'
        index_html += '<title>Diffing Summary</title>\n'
        index_html += '   <meta http-equiv="Content-Type" content="text/html; charset=utf-8">\n'
        index_html += '   <link rel="stylesheet" type="text/css" href="summary.css" />\n'
        index_html += '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">\n'
        index_html += '</head>\n'
        index_html += '<body>\n'
        index_html += '<div id="wrapper">\n'
        index_html += '<div id="pageHeaderFooter">Droidiffv2</div>\n'
        index_html += '<h1>Diffing Summary</h1>\n'
        index_html += '<p class="subheadding">HTML Report Generated on {}</p>\n'.format(datetime.datetime.now().strftime("%Y%m%d_%H%M"))
        index_html += '<div class="title">\n'
        index_html += '<div class="title">\n'
        index_html += '<div class="left">\n'
        index_html += '<table>\n'
        index_html += '<tbody>\n'
        index_html += '<tr><td class="block" style="width:auto">APK 1 path:</td><td>{}</td></tr>\n'.format(self.apk1_path)
        index_html += '<tr><td class="block" style="width:auto">APK 2 path:</td><td>{}</td></tr>\n'.format(self.apk2_path)
        index_html += '<tr><td class="block" style="width:auto">Duplicate search done in:</td><td>{}</td></tr>\n'.format(self.dupsearch_time)
        index_html += '<tr><td class="block" style="width:auto">Total time:</td><td>{}</td></tr>\n'.format(self.total_time)
        index_html += '<tr><td class="block" style="width:auto">Number of classes in APK1:</td><td>{}</td></tr>\n'.format(self.nb_classes_apk1)
        index_html += '<tr><td class="block" style="width:auto">Number of classes in APK2:</td><td>{}</td></tr>\n'.format(self.nb_classes_apk2)
        index_html += '</tbody></table>\n'
        index_html += '</div>\n'
        index_html += '<div class="clear"></div>\n'
        index_html += '</div>\n'
        index_html += '<div class="clear"></div>\n'
        index_html += '<h2>Information:</h2><div class="info">\n'
        index_html += '<table>\n'
        index_html += '<tbody>\n'
        index_html += '<tr><td>Similar classes:</td><td>{}</td></tr>\n'.format(len(self.classes_bulk))
        index_html += '<tr><td>Added classes:</td><td>{}</td></tr>\n'.format(len(self.classes_added))
        index_html += '<tr><td>Deleted classes:</td><td>{}</td></tr>\n'.format(len(self.classes_deleted))
        index_html += '<tr><td>Empty classes:</td><td>{}</td></tr>\n'.format(len(self.classes_empty))
        index_html += '</tbody></table>\n'
        index_html += '</div>\n'
        index_html += '<div>\n'
        index_html += '<div class="clear"></div></div>\n'
        index_html += '</div>\n'
        index_html += '<br><div id="pageHeaderFooter">Droidiffv2</div></body></html>\n'
        index_html += '\n'
        index_html += '\n'
        index_html += '\n'
        with open(self.comparison_result_folder + "/res/summary.html", "w") as f:
            f.write(index_html)
            
        nav_html = '<html>\n'
        nav_html += '<head>\n'
        nav_html += '    <title>Droidiffv2</title>\n'
        nav_html += '    <link rel="stylesheet" type="text/css" href="index.css" />\n'
        nav_html += '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">\n'
        nav_html += '</head>\n'
        nav_html += '<body>\n'
        nav_html += '<div id="content">\n'
        # TODO: add logo 
        #nav_html += '<img src="res/telefonica-new-2021-logo.png" width="60%" height="15%">\n'
        nav_html += '<h1>Menu</h1>\n'
        nav_html += '<ul class="nav">\n'
        nav_html += '<li><a href="summary.html" target="contents">Summary</a></li>\n'
        nav_html += '\n'
        nav_html += '<li><a href="similar_classes.html" target="contents">Similar Classes</a> ({})</li>\n'.format(len(self.classes_bulk))
        nav_html += '<li><a href="added_classes.html" target="contents">Added Classes</a> ({})</li>\n'.format(len(self.classes_added))
        nav_html += '<li><a href="deleted_classes.html" target="contents">Deleted Classes</a> ({})</li>\n'.format(len(self.classes_deleted))
        nav_html += '<li><a href="empty_classes.html" target="contents">Empty Classes</a> ({})</li>\n'.format(len(self.classes_empty))
        nav_html += '</ul>\n'
        nav_html += '</div>\n'
        nav_html += '</body>\n'
        nav_html += '</html>\n'
        with open(self.comparison_result_folder + "/res/nav.html", "w") as f:
            f.write(nav_html)
            
        similar_html = '<html>\n'
        similar_html += '<head>\n'
        similar_html += '	<title>Similar Classes</title>\n'
        similar_html += '	<link rel="stylesheet" type="text/css" href="index.css">\n'
        similar_html += '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">\n'
        similar_html += '</head>\n'
        similar_html += '<body>\n'
        similar_html += '<div>\n'
        similar_html += '<div id="pageHeaderFooter">Droidiffv2 Diffing Results</div>\n'
        similar_html += '<div id="header">Similar Classes</div>\n'
        similar_html += '\n'
        similar_html += '<div id="content">\n'
        similar_html += '<table>\n'
        similar_html += '<thead>\n'
        similar_html += '	<tr>\n'
        similar_html += '		<th>Class in APK1</th>\n'
        similar_html += '		<th>Class(es) in APK2</th>\n'
        similar_html += '		<th>Similarity Score</th>\n'
        similar_html += '	</tr>\n'
        similar_html += '</thead>\n'
        similar_html += '	<tbody>\n'
        similar_html += '<tr>\n'
        with open(self.comparison_result_folder + "/res/similar_classes.html" ,"w") as f:
            f.write(similar_html)
        similar_html = ''
        for similar in self.classes_similar:
            with open(self.comparison_result_folder + "/res/similar_classes.html" ,"a") as f:
                similar_html = '<tr>\n'
                similar_html += '<td>{}</td>\n'.format(similar)
                similar_html += '<td class="left_align_cell">\n'
                similar_html += '<ul>\n'
                for candidate in self.classes_similar[similar]['candidates']:
                    similar_html += '<li>{}</li>\n'.format(candidate)
                similar_html += '</ul>\n'
                similar_html += '</td>\n'
                similar_html += '<td>{}</td>\n'.format(self.classes_similar[similar]['score'])
                similar_html += '</tr>\n'
                f.write(similar_html)
        similar_html = ''
        similar_html += '</tbody></table>\n'
        similar_html += '<br>\n'
        similar_html += '<div id="pageHeaderFooter">Droidiffv2</div>\n'
        similar_html += '</div>\n'
        similar_html += '</body>\n'
        similar_html += '</html>\n'
        with open(self.comparison_result_folder + "/res/similar_classes.html" ,"a") as f:
            f.write(similar_html)
        
        added_html = '<html>\n'
        added_html += '<head>\n'
        added_html += '	<title>Added Classes</title>\n'
        added_html += '	<link rel="stylesheet" type="text/css" href="index.css">\n'
        added_html += '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">\n'
        added_html += '</head>\n'
        added_html += '<body>\n'
        added_html += '<div>\n'
        added_html += '<div id="pageHeaderFooter">Droidiffv2 Diffing Results</div>\n'
        added_html += '<div id="header">Added Classes</div>\n'
        added_html += '\n'
        added_html += '<div id="content">\n'
        added_html += '<table>\n'
        added_html += '<thead>\n'
        added_html += '	<tr>\n'
        added_html += '		<th>Class in APK2</th>\n'
        added_html += '	</tr>\n'
        added_html += '</thead>\n'
        added_html += '	<tbody>\n'
        added_html += '\n'
        with open(self.comparison_result_folder + "/res/added_classes.html", "w") as f:
            f.write(added_html)
        for added_class in sorted(self.classes_added):
            with open(self.comparison_result_folder + "/res/added_classes.html", "a") as f:
                f.write('<tr><td>{}</td></tr>\n'.format(added_class))
        added_html = '</tbody></table>\n'
        added_html += '<br>\n'
        added_html += '<div id="pageHeaderFooter">Droidiffv2</div>\n'
        added_html += '</div>\n'
        added_html += '</body>\n'
        added_html += '</html>\n'        
        with open(self.comparison_result_folder + "/res/added_classes.html", "a") as f:
            f.write(added_html)
               
        deleted_html = '<html>\n'
        deleted_html += '<head>\n'
        deleted_html += '	<title>Deleted Classes</title>\n'
        deleted_html += '	<link rel="stylesheet" type="text/css" href="index.css">\n'
        deleted_html += '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">\n'
        deleted_html += '</head>\n'
        deleted_html += '<body>\n'
        deleted_html += '<div>\n'
        deleted_html += '<div id="pageHeaderFooter">Droidiffv2 Diffing Results</div>\n'
        deleted_html += '<div id="header">Deleted Classes</div>\n'
        deleted_html += '\n'
        deleted_html += '<div id="content">\n'
        deleted_html += '<table>\n'
        deleted_html += '<thead>\n'
        deleted_html += '	<tr>\n'
        deleted_html += '		<th>Class in APK1</th>\n'
        deleted_html += '	</tr>\n'
        deleted_html += '</thead>\n'
        deleted_html += '	<tbody>\n'
        deleted_html += '\n'
        with open(self.comparison_result_folder + "/res/deleted_classes.html", "w") as f:
            f.write(deleted_html)
        for deleted_class in sorted(self.classes_deleted):
            with open(self.comparison_result_folder + "/res/deleted_classes.html", "a") as f:
                f.write('<tr><td>{}</td></tr>\n'.format(deleted_class))
        deleted_html = '</tbody></table>\n'
        deleted_html += '<br>\n'
        deleted_html += '<div id="pageHeaderFooter">Droidiffv2</div>\n'
        deleted_html += '</div>\n'
        deleted_html += '</body>\n'
        deleted_html += '</html>\n'        
        with open(self.comparison_result_folder + "/res/deleted_classes.html", "a") as f:
            f.write(deleted_html)          

        empty_html = '<html>\n'
        empty_html += '<head>\n'
        empty_html += '	<title>Empty Classes</title>\n'
        empty_html += '	<link rel="stylesheet" type="text/css" href="index.css">\n'
        empty_html += '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">\n'
        empty_html += '</head>\n'
        empty_html += '<body>\n'
        empty_html += '<div>\n'
        empty_html += '<div id="pageHeaderFooter">Droidiffv2 Diffing Results</div>\n'
        empty_html += '<div id="header">Empty Classes</div>\n'
        empty_html += '\n'
        empty_html += '<div id="content">\n'
        empty_html += '<table>\n'
        empty_html += '<thead>\n'
        empty_html += '	<tr>\n'
        empty_html += '		<th>Class in APK1</th>\n'
        empty_html += '	</tr>\n'
        empty_html += '</thead>\n'
        empty_html += '	<tbody>\n'
        empty_html += '\n'
        with open(self.comparison_result_folder + "/res/empty_classes.html", "w") as f:
            f.write(empty_html)
        for empty_class in sorted(self.classes_empty):
            with open(self.comparison_result_folder + "/res/empty_classes.html", "a") as f:
                f.write('<tr><td>{}</td></tr>\n'.format(empty_class))
        empty_html = '</tbody></table>\n'
        empty_html += '<br>\n'
        empty_html += '<div id="pageHeaderFooter">Droidiffv2</div>\n'
        empty_html += '</div>\n'
        empty_html += '</body>\n'
        empty_html += '</html>\n'        
        with open(self.comparison_result_folder + "/res/empty_classes.html", "a") as f:
            f.write(empty_html) 
            
        index_css = 'body {margin: 0px; padding: 0px; background: #FFFFFF; font: 13px/20px Arial, Helvetica, sans-serif; color: #535353;}'
        index_css += '#content {padding: 30px;}'
        index_css += '#header {width:100%; padding: 10px; line-height: 25px; background: #07A; color: #FFF; font-size: 20px;}'
        index_css += '#pageHeaderFooter {width: 100%; padding: 10px; line-height: 25px; text-align: center; font-size: 20px;}'
        index_css += 'h1 {font-size: 20px; font-weight: normal; color: #07A; padding: 0 0 7px 0; margin-top: 25px; border-bottom: 1px solid #D6D6D6;}'
        index_css += 'h2 {font-size: 20px; font-weight: bolder; color: #07A;}'
        index_css += 'h3 {font-size: 16px; color: #07A;}'
        index_css += 'h4 {background: #07A; color: #FFF; font-size: 16px; margin: 0 0 0 25px; padding: 0; padding-left: 15px;}'
        index_css += 'ul.nav {list-style-type: none; line-height: 35px; padding: 0px; margin-left: 15px;}'
        index_css += 'ul li a {font-size: 14px; color: #444; text-decoration: none; padding-left: 25px;}'
        index_css += 'ul li a:hover {text-decoration: underline;}'
        index_css += 'p {margin: 0 0 20px 0;}'
        index_css += 'table {white-space:nowrap; width: 100%; padding: 2; margin: 0; border-collapse: collapse; border-bottom: 2px solid #e5e5e5;}'
        index_css += '.keyword_list table {margin: 0 0 25px 25px; border-bottom: 2px solid #dedede;}'
        index_css += 'table th {white-space:nowrap; display: table-cell; text-align: center; padding: 2px 4px; background: #e5e5e5; color: #777; font-size: 11px; text-shadow: #e9f9fd 0 1px 0; border-top: 1px solid #dedede; border-bottom: 2px solid #e5e5e5;}'
        index_css += 'table .left_align_cell{display: table-cell; padding: 2px 4px; font: 13px/20px Arial, Helvetica, sans-serif; min-width: 70px; overflow: auto; text-align: left; }'
        index_css += 'table .right_align_cell{display: table-cell; padding: 2px 4px; font: 13px/20px Arial, Helvetica, sans-serif; min-width: 70px; overflow: auto; text-align: right; }'
        index_css += 'table td {white-space:nowrap; display: table-cell; padding: 2px 3px; font: 13px/20px Arial, Helvetica, sans-serif; min-width: 30px; overflow: auto; text-align:left; vertical-align: text-top;}'
        index_css += 'table tr:nth-child(even) td {background: #f3f3f3;}'
        index_css += 'div#thumbnail_link {max-width: 200px; white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;}'        
        with open(self.comparison_result_folder + "/res/index.css","w") as f:
            f.write(index_css)
        
        summary_css = '#pageHeaderFooter {width: 100%; padding: 10px; line-height: 25px; text-align: center; font-size: 20px;}'
        summary_css += 'body { padding: 0px; margin: 0px; font: 13px/20px Arial, Helvetica, sans-serif; color: #535353; }'
        summary_css += '#wrapper { width: 90%; margin: 0px auto; margin-top: 35px; }'
        summary_css += 'h1 { color: #07A; font-size: 36px; line-height: 42px; font-weight: normal; margin: 0px; border-bottom: 1px solid #81B9DB; }'
        summary_css += 'h1 span { color: #F00; display: block; font-size: 16px; font-weight: bold; line-height: 22px;}'
        summary_css += 'h2 { padding: 0 0 3px 0; margin: 0px; color: #07A; font-weight: normal; border-bottom: 1px dotted #81B9DB; }'
        summary_css += 'h3 { padding: 5 0 3px 0; margin: 0px; color: #07A; font-weight: normal; }'
        summary_css += 'table td { padding: 5px 25px 5px 0px; vertical-align:top;}'
        summary_css += 'p.subheadding { padding: 0px; margin: 0px; font-size: 11px; color: #B5B5B5; }'
        summary_css += '.title { width: 660px; margin-bottom: 50px; }'
        summary_css += '.left { float: left; width: auto; margin-top: 20px; text-align: center; }'
        summary_css += '.left img { max-width: 250px; max-height: 250px; min-width: 200px; min-height: 200px; }'
        summary_css += '.right { float: right; width: 385px; margin-top: 25px; font-size: 14px; }'
        summary_css += '.clear { clear: both; }'
        summary_css += '.info { padding: 10px 0;}'
        summary_css += '.info p { padding: 3px 10px; background: #e5e5e5; color: #777; font-size: 12px; font-weight: bold; text-shadow: #e9f9fd 0 1px 0; border-top: 1px solid #dedede; border-bottom: 2px solid #dedede; }'
        summary_css += '.info table { margin: 10px 25px 10px 25px; }'
        summary_css += 'ul {padding: 0;margin: 0;list-style-type: none;}li {padding-bottom: 5px;}'
        with open(self.comparison_result_folder + "/res/summary.css","w") as f:
            f.write(summary_css)

def main():
    argparser = argparse.ArgumentParser(description=DROIDBANNER,
                                        formatter_class=argparse.RawDescriptionHelpFormatter
                                        )
    argparser.add_argument('--excpkgs',
                       type=str,
                       help='''Packages names (string) separated by semicolons being excluded in the comparison for better performance (watch out for obfuscation).
                       Example: --excpkgs="com/google/android/;android/support/;androidx/"
                       ''')
    argparser.add_argument('-f',
                           type=str,
                           help="Txt file where excluded packages are located. One package per line.")
    argparser.add_argument('apk1_path',
                           type=str,
                           help="Path to the first apk for the comparison.")
    argparser.add_argument('apk2_path',
                           type=str,
                           help="Path to the second apk for the comparison.")
    argparser.add_argument('-o',
                           action="store_true",
                           help="If the apks are name obfuscated. (not in use)")
    argparser.add_argument('-k',
                           type=int,
                           default=3,
                           help="Hamming distance used for bulk comparison (default=3).")
    argparser.add_argument('-t',
                           type=float,
                           default=0.8,
                           help="Threshold for candidates during accute comparison (default=0.8).")
    args = argparser.parse_args()
    excluded_packages = []
    print(DROIDBANNER)
    comparison_config = {}
    if args.f:
        temp = []
        with open(args.f, "r") as file:
            temp = file.readlines()
            for i in temp:
                excluded_packages.append(i.replace("\n",""))
    if args.excpkgs:
        excluded_packages.append(args.excpkgs)
    if excluded_packages:
        comparison_config["excluded_packages"] = excluded_packages
    else:
        comparison_config["excluded_packages"] = None
    comparison_config["hamming_distance"] = args.k
    comparison_config["threshold"] = args.t
    comparison_config["obfuscated"] = args.o
    create_folder("outputs", "Created outputs folder")
    comparison = apk_comparison(args.apk1_path, args.apk2_path, comparison_config)
    print(comparison_config)
    comparison.compare()
    
    
    pass

if __name__ == '__main__':
    main()