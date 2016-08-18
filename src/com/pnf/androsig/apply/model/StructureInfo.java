/*
 * JEB Copyright PNF Software, Inc.
 * 
 *     https://www.pnfsoftware.com
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.pnf.androsig.apply.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;

import com.pnf.androsig.apply.util.MetadataGroupHandler;
import com.pnf.androsig.apply.util.StructureHandler;
import com.pnf.androsig.common.SignatureHandler;
import com.pnfsoftware.jeb.core.output.ItemClassIdentifiers;
import com.pnfsoftware.jeb.core.units.code.IInstruction;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexCodeItem;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethodData;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexPrototype;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * The class contains all information about the project structure.
 * 
 * @author Ruoxiao Wang
 *
 */
public class StructureInfo {
    private final ILogger logger = GlobalLog.getLogger(StructureInfo.class);

    // Parameters
    public int methodSizeBar = 0; // will skip method if its instruction size is no great than methodSizeBar
    public double matchedInstusPercentageBar = 0; // will skip the class if (total matched instructions / total instructions) is no greater than matchedMethodsPercentageBar

    // class index --- classPath_sig
    private Map<Integer, String> matchedClasses;
    // method index --- methodName_sig
    private Map<Integer, String> matchedMethods;

    // method map (method.getSignature(false), method.getSignature(true))
    // used by DexMetadataGroup
    private Map<String, String> matchedMethods_new_orgPath;
    private Map<String, String> matchedClasses_new_orgPath;

    // Modified classes
    private Set<Integer> modifiedClasses;

    private Map<Integer, Map<Integer, Integer>> apkCallerLists;

    private Map<Integer, String[]> methodHashcodes;

    // **** Rebuild structure ****
    // class index --- candidates (uncertain classes after version one matching)
    private Map<Integer, Set<String>> uncertainMatchedClasses = new HashMap<>();
    // Check duplicate classes (if two or more classes match to the same library class, we need to avoid rename these classes)
    private Map<String, ArrayList<Integer>> dupClasses = new HashMap<>();
    // Check duplicate methods (same as dupClass)
    private Map<Integer, ArrayList<Integer>> dupMethods = new HashMap<>();
    // class path sig --- count
    private Map<String, Integer> classPathCount = new HashMap<>();
    // class path sig --- method index --- method names
    private Map<String, Map<Integer, Set<String>>> classPathMethod = new HashMap<>();
    // Duplicate class checker
    private Map<Integer, List<String>> classPathCandidateFilter = new HashMap<>();

    private Set<String> dupChecker = new HashSet<>();

    private Map<Integer, Double> instruCount;

    private Map<String, List<String[]>> allTightSignatures;
    private Map<String, List<String[]>> allLooseSignatures;

    public StructureInfo() {
        matchedClasses = new HashMap<>();

        matchedMethods = new HashMap<>();

        matchedMethods_new_orgPath = new HashMap<>();
        matchedClasses_new_orgPath = new HashMap<>();

        modifiedClasses = new HashSet<Integer>();

        apkCallerLists = new HashMap<>();
        methodHashcodes = new HashMap<>();

        instruCount = new HashMap<>();
    }

    /**
     * Get all matched classes.
     * 
     * @return a Map (key: index of a class. Value: a set of all matched classes(path))
     */
    public Map<Integer, String> getMatchedClasses() {
        return matchedClasses;
    }

    /**
     * Get all matched methods.
     * 
     * @return a Map (Key: index of a method. Value: actual name of a method)
     */
    public Map<Integer, String> getMatchedMethods() {
        return matchedMethods;
    }

    /**
     * Get method original signature through new signature
     * 
     * @return a Map (Key: method new signature. Value: method original signature)
     */
    public Map<String, String> getMatchedMethods_new_orgPath() {
        return matchedMethods_new_orgPath;
    }

    /**
     * Get class original signature through new signature
     * 
     * @return a Map (Key: class new signature. Value: class original signature)
     */
    public Map<String, String> getMatchedClasses_new_orgPath() {
        return matchedClasses_new_orgPath;
    }

    /**
     * Load all current apk hash codes.
     * 
     * @param unit mandatory target unit
     */
    public void loadAPKHashcodes(IDexUnit unit) {
        List<? extends IDexClass> classes = unit.getClasses();
        if(classes == null || classes.size() == 0) {
            return;
        }
        for(IDexClass eClass: classes) {
            List<? extends IDexMethod> methods = eClass.getMethods();
            if(methods == null || methods.size() == 0)
                continue;
            for(IDexMethod m: methods) {
                if(!m.isInternal()) {
                    continue;
                }
                IDexMethodData md = m.getData();
                if(md == null) {
                    continue;
                }
                IDexCodeItem ci = md.getCodeItem();
                if(ci == null) {
                    methodHashcodes.put(m.getIndex(), new String[]{"null", "null"});
                }
                else {
                    methodHashcodes.put(m.getIndex(), new String[]{SignatureHandler.generateTightHashcode(ci),
                            SignatureHandler.generateLooseHashcode(ci)});
                }
            }
        }
    }

    /**
     * Rebuild project structure using signatures.
     * 
     * @param unit mandatory target unit
     * @param sig Signature Object
     */
    public void rebuildStructure(IDexUnit unit, Signature sig) {
        logger.info("methodSizeBar " + methodSizeBar);
        logger.info("matchedInstusPercentageBar " + matchedInstusPercentageBar);

        // First Round using tight signature and loose signature
        logger.info("Signature matching 1 start...");
        final long startTime = System.currentTimeMillis();

        matchingVerOne(unit, sig);

        final long endTime = System.currentTimeMillis();
        logger.info("Signature matching 1 start completed! (Execution Time: " + (endTime - startTime) / 1000 + "s)");

        logger.info("******************************************************************");

        // Following Rounds using caller list
        logger.info("Signature matching 2 start...");
        final long startTime1 = System.currentTimeMillis();

        if(Thread.currentThread().isInterrupted()) {
            return;
        }

        matchingVerTwo(unit, sig);

        final long endTime1 = System.currentTimeMillis();
        logger.info("Signature matching 2 start completed! (Execution Time: " + (endTime1 - startTime1) / 1000 + "s)");

        // Move exceptional classes
        moveExceptionalClasses(unit);
        // Store all matched methods
        storeAllMatchedMethods_new_orgPath(unit);
        // Store all matched classes
        storeAllMatchedClasses_new_orgPath(unit);
    }

    private void matchingVerOne(IDexUnit unit, Signature sig) {
        storeMatchedClassesAndMethods(unit, sig, true);
        // rename matched classes and methods
        renameMatchedClassesAndMethods(unit);
        // rename matched packages
        renameMatchedPackages(unit);

        // rename small methods
        renameSmallMethods(unit);

        SignatureHandler.loadAllCallerLists(unit, apkCallerLists, matchedClasses, matchedMethods);
    }

    private void matchingVerTwo(IDexUnit unit, Signature sig) {
        int matchedClassCount = matchedClasses.size();
        logger.info("After matching ver 1 SIZE: " + matchedClasses.size());
        while(true) {
            storeMatchedClassesAndMethods(unit, sig, false);
            renameMatchedClassesAndMethods(unit);
            renameMatchedPackages(unit);
            renameSmallMethods(unit);
            logger.info("SIZE: " + matchedClasses.size());
            if(matchedClasses.size() == matchedClassCount) {
                break;
            }
            else {
                matchedClassCount = matchedClasses.size();
            }
            SignatureHandler.loadAllCallerLists(unit, apkCallerLists, matchedClasses, matchedMethods);
        }
    }

    private void storeMatchedClassesAndMethods(IDexUnit unit, Signature sig, boolean firstRound) {
        List<? extends IDexClass> classes = unit.getClasses();
        if(classes == null || classes.size() == 0) {
            return;
        }
        // Get signature maps       
        getSignatures(sig);
        for(IDexClass eClass: classes) {
            if(matchedClasses.containsKey(eClass.getIndex())) {
                continue;
            }
            // Get all candidates
            if(applySignatures(unit, eClass, sig, firstRound)) {
                findAndStoreFinalCandidate(unit, eClass, firstRound);
            }

            classPathCount.clear();
            classPathMethod.clear();
            dupChecker.clear();
        }
        // remove duplicates
        for(Entry<String, ArrayList<Integer>> eClass: dupClasses.entrySet()) {
            if(eClass.getValue().size() != 1) {
                for(Integer e: eClass.getValue()) {
                    // remove class
                    matchedClasses.remove(e);
                    // remove methods
                    for(Integer eMethod: dupMethods.get(e)) {
                        matchedMethods.remove(eMethod);
                    }
                }
            }
        }
        // GC
        dupClasses.clear();
        dupMethods.clear();
        classPathCount.clear();
        classPathMethod.clear();
        dupChecker.clear();
    }

    private void getSignatures(Signature sig) {
        allLooseSignatures = sig.getAllLooseSignatures();
        allTightSignatures = sig.getAllTightSignatures();
    }

    private boolean applySignatures(IDexUnit dex, IDexClass eClass, Signature sig, boolean firstRound) {
        List<? extends IDexMethod> methods = eClass.getMethods();
        if(methods == null || methods.size() == 0) {
            return false;
        }

        boolean flag = false;
        for(IDexMethod eMethod: methods) {
            if(!eMethod.isInternal()) {
                continue;
            }

            if(matchedMethods.containsKey(eMethod.getIndex())) {
                continue;
            }

            // The second round
            if(!firstRound && !apkCallerLists.containsKey(eMethod.getIndex())) {
                continue;
            }

            List<? extends IInstruction> instructions = eMethod.getInstructions();
            if(instructions == null || instructions.size() <= methodSizeBar) {
                continue;
            }

            String[] hashcodes = methodHashcodes.get(eMethod.getIndex());
            if(hashcodes == null) {
                continue;
            }

            List<String[]> elts = allTightSignatures.get(hashcodes[0]);

            if(elts != null
                    && applySignatures_innerLoop(dex, sig, eMethod, elts, classPathCount, classPathMethod, dupChecker,
                            firstRound)) {
                flag = true;
            }
            else {
                elts = allLooseSignatures.get(hashcodes[1]);
                if(elts != null
                        && applySignatures_innerLoop(dex, sig, eMethod, elts, classPathCount, classPathMethod,
                                dupChecker, firstRound)) {
                    flag = true;
                }
            }
        }
        return flag;
    }

    private boolean applySignatures_innerLoop(IDexUnit dex, Signature sig, IDexMethod eMethod, List<String[]> elts,
            Map<String, Integer> classPathCount_map, Map<String, Map<Integer, Set<String>>> classPathMethod_map,
            Set<String> dupChecker, boolean firstRound) {
        IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
        String shorty = proto.getShorty();
        String prototype = proto.generate(true);
        boolean flag = false;

        dupChecker.clear();

        if(firstRound) {
            // One class has several same sigs
            for(String[] strArray: elts) {
                if(!strArray[2].equals(shorty) || !strArray[3].equals(prototype)) {
                    continue;
                }
                flag = true;
                storeEachCandidate(strArray[0], strArray[1], classPathCount_map, classPathMethod_map, dupChecker,
                        eMethod);
            }
        }
        else {
            Map<Integer, Integer> callerList = apkCallerLists.get(eMethod.getIndex());

            // Go through each signature
            TreeMap<Integer, ArrayList<String[]>> map = new TreeMap<>(Collections.reverseOrder());
            Map<String, Integer> targetCallerList = new HashMap<>();

            for(String[] strArray: elts) {
                if(!strArray[2].equals(shorty) || !strArray[3].equals(prototype)) {
                    continue;
                }
                String targetCaller = strArray[4];
                if(targetCaller.equals("")) {
                    continue;
                }
                flag = true;
                int count = 0;
                String[] targetCallers = targetCaller.split("\\|");
                targetCallerList.clear();
                for(int i = 0; i < targetCallers.length; i++) {
                    targetCallerList.put(targetCallers[i].split("=")[0],
                            Integer.parseInt(targetCallers[i].split("=")[1]));
                }
                for(Map.Entry<Integer, Integer> each: callerList.entrySet()) {
                    String methodPath = dex.getMethod(each.getKey()).getSignature(true);
                    if(targetCallerList.containsKey(methodPath)) {
                        if(targetCallerList.get(methodPath) == each.getValue()) {
                            count++;
                        }
                    }
                }
                ArrayList<String[]> temp = map.get(count);
                if(temp != null) {
                    temp.add(strArray);
                }
                else {
                    ArrayList<String[]> temp1 = new ArrayList<String[]>();
                    temp1.add(strArray);
                    map.put(count, temp1);
                }
            }
            if(!map.isEmpty()) {
                for(String[] each: map.firstEntry().getValue()) {
                    storeEachCandidate(each[0], each[1], classPathCount_map, classPathMethod_map, dupChecker, eMethod);
                }
            }
        }
        return flag;
    }

    private void storeEachCandidate(String classPath, String methodName, Map<String, Integer> classPathCount,
            Map<String, Map<Integer, Set<String>>> classPathMethod, Set<String> dupChecker, IDexMethod eMethod) {
        // Store class
        Integer count = classPathCount.get(classPath);
        if(count == null) {
            dupChecker.add(classPath);
            classPathCount.put(classPath, 1);
        }
        else {
            if(!dupChecker.contains(classPath)) {
                dupChecker.add(classPath);
                classPathCount.put(classPath, count + 1);
            }
        }
        // store methods
        Map<Integer, Set<String>> temp = classPathMethod.get(classPath);
        if(temp == null) {
            Map<Integer, Set<String>> tempMap = new HashMap<>();
            Set<String> tempList = new HashSet<>();
            tempList.add(methodName);
            tempMap.put(eMethod.getIndex(), tempList);
            classPathMethod.put(classPath, tempMap);
        }
        else {
            Set<String> temp1 = temp.get(eMethod.getIndex());
            if(temp1 == null) {
                HashSet<String> temp2 = new HashSet<>();
                temp2.add(methodName);
                classPathMethod.get(classPath).put(eMethod.getIndex(), temp2);
            }
            else {
                temp1.add(methodName);
            }
        }
    }

    private void findAndStoreFinalCandidate(IDexUnit unit, IDexClass eClass, boolean firstRound) {
        classPathCandidateFilter.clear();
        if(classPathCount == null || classPathCount.size() == 0) {
            return;
        }
        int max = 0;
        for(Map.Entry<String, Integer> each: classPathCount.entrySet()) {
            if(each.getValue() > max) {
                max = each.getValue();
            }
            List<String> tempSet = classPathCandidateFilter.get(each.getValue());
            if(tempSet == null) {
                List<String> temp1 = new ArrayList<>();
                temp1.add(each.getKey());
                classPathCandidateFilter.put(each.getValue(), temp1);
            }
            else {
                tempSet.add(each.getKey());
            }
        }
        List<String> classPathCandidates = classPathCandidateFilter.get(max);

        if(firstRound) {
            // Store classes
            // handle "support package" library "internal package" exception
            if(classPathCandidates.size() == 2) {
                // If signatures are from android.support package
                String c1 = classPathCandidates.get(0);
                String c2 = classPathCandidates.get(1);
                if(c1.startsWith("Landroid/support/") && c2.startsWith("Landroid/support/")
                        && (c1.contains("/internal") || c2.contains("/internal"))) {
                    if(c1.replace("/internal", "").equals(c2.replace("/internal", ""))) {
                        classPathCandidates.clear();
                        if(c1.contains("/internal")) {
                            classPathCandidates.add(c2);
                        }
                        else {
                            classPathCandidates.add(c1);
                        }
                    }
                }
            }
        }
        else {
            Set<String> temp1 = uncertainMatchedClasses.get(eClass.getIndex());
            if(temp1 != null) {
                classPathCandidates.retainAll(temp1);
                if(classPathCandidates.size() == 1) {
                    uncertainMatchedClasses.remove(eClass.getIndex());
                }
            }
        }

        if(classPathCandidates.size() != 1) {
            uncertainMatchedClasses.put(eClass.getIndex(), new HashSet<String>(classPathCandidates));
            return;
        }

        String classPath_sig_final = classPathCandidates.iterator().next();

        // Store methods
        ArrayList<Integer> temp1 = new ArrayList<Integer>();
        Map<Integer, Set<String>> methodName_methods = classPathMethod.get(classPath_sig_final);
        if(methodName_methods == null || methodName_methods.size() == 0) {
            return;
        }
        for(Map.Entry<Integer, Set<String>> methodName_method: methodName_methods.entrySet()) {
            if(methodName_method.getValue() == null || methodName_method.getValue().size() != 1) {
                continue;
            }
            temp1.add(methodName_method.getKey());
            matchedMethods.put(methodName_method.getKey(), methodName_method.getValue().iterator().next());
        }

        if(temp1.size() != 0) {
            if(f(unit, eClass, temp1)) {
                matchedClasses.put(eClass.getIndex(), classPath_sig_final);
                ArrayList<Integer> tempArrayList = dupClasses.get(classPath_sig_final);
                if(tempArrayList != null) {
                    tempArrayList.add(eClass.getIndex());
                    dupClasses.put(classPath_sig_final, tempArrayList);
                }
                else {
                    ArrayList<Integer> temp2 = new ArrayList<Integer>();
                    temp2.add(eClass.getIndex());
                    dupClasses.put(classPath_sig_final, temp2);
                }
                dupMethods.put(eClass.getIndex(), temp1);
            }
            else {
                for(int e: temp1) {
                    matchedMethods.remove(e);
                }
            }
        }
    }

    private boolean f(IDexUnit unit, IDexClass eClass, ArrayList<Integer> matchedMethods) {
        double totalInstrus = 0;
        double matchedInstrus = 0;

        Double c = instruCount.get(eClass.getIndex());
        if(c != null) {
            totalInstrus = c;
            for(int e: matchedMethods) {
                matchedInstrus += unit.getMethod(e).getInstructions().size();
            }
        }
        else {
            List<? extends IDexMethod> methods = eClass.getMethods();
            if(methods == null || methods.size() == 0) {
                return false;
            }
            for(IDexMethod m: methods) {
                if(!m.isInternal()) {
                    continue;
                }

                IDexMethodData md = m.getData();
                if(md == null) {
                    continue;
                }
                IDexCodeItem ci = md.getCodeItem();
                if(ci == null) {
                    continue;
                }
                int count = ci.getInstructions().size();
                if(matchedMethods.contains(m.getIndex())) {
                    matchedInstrus += count;
                }
                totalInstrus += count;
                instruCount.put(eClass.getIndex(), totalInstrus);
            }
        }

        if(matchedInstrus / totalInstrus <= matchedInstusPercentageBar) {
            return false;
        }
        return true;
    }

    private void renameMatchedClassesAndMethods(IDexUnit unit) {
        List<? extends IDexClass> classes = unit.getClasses();
        if(classes == null || classes.size() == 0) {
            return;
        }
        for(IDexClass eClass: classes) {
            if(modifiedClasses.contains(eClass.getIndex())) {
                continue;
            }
            if(matchedClasses.containsKey(eClass.getIndex())) {
                // Rename class
                String classPath_sig = matchedClasses.get(eClass.getIndex());
                String className = classPath_sig.substring(classPath_sig.lastIndexOf("/") + 1,
                        classPath_sig.length() - 1);
                StructureHandler.rename(unit, className, eClass.getItemId());
                MetadataGroupHandler.getCodeGroupClass(unit).setData(eClass.getSignature(false),
                        ItemClassIdentifiers.CODE_ROUTINE.getId());
                modifiedClasses.add(eClass.getIndex());

                // Rename methods
                List<? extends IDexMethod> methods = eClass.getMethods();
                if(methods == null || methods.size() == 0) {
                    continue;
                }

                if(matchedMethods == null || matchedMethods.size() == 0) {
                    continue;
                }

                for(IDexMethod eMethod: methods) {
                    String temp = matchedMethods.get(eMethod.getIndex());
                    if(temp != null) {
                        StructureHandler.rename(unit, temp, eMethod.getItemId());
                        MetadataGroupHandler.getCodeGroupMethod(unit).setData(eMethod.getSignature(false),
                                ItemClassIdentifiers.CODE_LIBRARY.getId());
                    }
                }
            }
        }
    }

    private void renameMatchedPackages(IDexUnit unit) {
        if(matchedClasses == null || matchedClasses.size() == 0) {
            return;
        }
        for(Map.Entry<Integer, String> eClass: matchedClasses.entrySet()) {
            String packagePath = eClass.getValue().substring(0, eClass.getValue().lastIndexOf("/")) + ";";
            StructureHandler.createPackage(unit, packagePath);
            StructureHandler.moveClass(unit, packagePath, unit.getClass(eClass.getKey()).getItemId());
        }
    }

    private void renameSmallMethods(IDexUnit unit) {
        Map<String, Integer> map = new HashMap<>();
        TreeMap<Integer, ArrayList<String>> treemap = new TreeMap<>(Collections.reverseOrder());
        for(int cIndex: matchedClasses.keySet()) {
            IDexClass eClass = unit.getClass(cIndex);
            String classPath = eClass.getSignature(true);
            List<? extends IDexMethod> methods = eClass.getMethods();
            for(IDexMethod method: methods) {
                if(matchedMethods.containsKey(method.getIndex())) {
                    continue;
                }
                map.clear();
                treemap.clear();
                IDexPrototype proto = unit.getPrototypes().get(method.getPrototypeIndex());
                String shorty = unit.getStrings().get(proto.getShortyIndex()).getValue();
                String[] hashcodes = methodHashcodes.get(method.getIndex());
                if(hashcodes == null) {
                    continue;
                }
                List<String[]> sigs = allTightSignatures.get(hashcodes[0]);
                String methodName = null;
                if(sigs != null) {
                    methodName = findMethodName(map, treemap, sigs, shorty, classPath);
                }
                if(methodName == null) {
                    sigs = allLooseSignatures.get(hashcodes[1]);
                    if(sigs != null) {
                        methodName = findMethodName(map, treemap, sigs, shorty, classPath);
                    }
                }
                if(methodName != null) {
                    matchedMethods.put(method.getIndex(), methodName);
                    StructureHandler.rename(unit, methodName, method.getItemId());
                    MetadataGroupHandler.getCodeGroupMethod(unit).setData(method.getSignature(false),
                            ItemClassIdentifiers.CODE_LIBRARY.getId());
                }
            }
        }
    }

    private String findMethodName(Map<String, Integer> map, TreeMap<Integer, ArrayList<String>> treemap,
            List<String[]> sigs, String shorty, String classPath) {
        for(String[] strArray: sigs) {
            if(!strArray[2].equals(shorty)) {
                continue;
            }
            if(!strArray[0].equals(classPath)) {
                continue;
            }
            Integer count = map.get(strArray[1]);
            if(count == null) {
                map.put(strArray[1], 1);
            }
            else {
                map.put(strArray[1], count + 1);
            }
        }
        for(Map.Entry<String, Integer> entry: map.entrySet()) {
            String mName = entry.getKey();
            int count = entry.getValue();
            ArrayList<String> temp = treemap.get(count);
            if(temp == null) {
                ArrayList<String> temp1 = new ArrayList<>();
                temp1.add(mName);
                treemap.put(count, temp1);
            }
            else {
                temp.add(mName);
                treemap.put(count, temp);
            }
        }
        Entry<Integer, ArrayList<String>> finalList = treemap.firstEntry();
        if(finalList == null)
            return null;
        if(finalList.getValue().size() == 1) {
            return finalList.getValue().get(0);
        }
        return null;
    }

    private void moveExceptionalClasses(IDexUnit unit) {
        List<? extends IDexClass> classes = unit.getClasses();
        if(classes == null || classes.size() == 0) {
            return;
        }
        for(IDexClass eClass: classes) {
            int classIndex = eClass.getIndex();
            if(!matchedClasses.containsKey(classIndex)) {
                continue;
            }
            String classSigPath = matchedClasses.get(classIndex);
            // If the class is located in the right package, continue
            if(classSigPath.equals(eClass.getSignature(true))) {
                continue;
            }
            String packageSigPath = classSigPath.substring(0, classSigPath.lastIndexOf("/")) + ";";
            StructureHandler.createPackage(unit, packageSigPath);
            StructureHandler.moveClass(unit, packageSigPath, eClass.getItemId());
        }
    }

    private void storeAllMatchedMethods_new_orgPath(IDexUnit unit) {
        for(int each: matchedMethods.keySet()) {
            IDexMethod method = unit.getMethod(each);
            matchedMethods_new_orgPath.put(method.getSignature(true), method.getSignature(false));
        }
    }

    private void storeAllMatchedClasses_new_orgPath(IDexUnit unit) {
        for(int each: matchedClasses.keySet()) {
            IDexClass eClass = unit.getClass(each);
            matchedClasses_new_orgPath.put(eClass.getSignature(true), eClass.getSignature(false));
        }
    }
}
