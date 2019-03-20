/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;

import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.DexHashcodeList;
import com.pnf.androsig.apply.model.MethodSignature;
import com.pnfsoftware.jeb.core.units.code.IInstruction;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexCodeItem;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethodData;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexPrototype;

/**
 * Aims at building the matched classes and signature in a {@link IDexUnit}. No modification is made
 * on {@link IDexUnit}, the purpose of this class is only to find matches. Call
 * {@link #storeMatchedClassesAndMethods(IDexUnit, Signature, DexHashcodeList, boolean)} to perform
 * analysis. See {@link #getMatchedClasses()} and {@link #getMatchedMethods()} for results.
 * 
 * @author Ruoxiao Wang, Cedric Lucas
 *
 */
class DatabaseMatcher implements IDatabaseMatcher {

    private DatabaseMatcherParameters params;
    private Signature sig;
    private DatabaseReference ref;
    // class index --- classPath_sig
    private Map<Integer, String> matchedClasses = new HashMap<>();
    // method index --- methodName_sig
    private Map<Integer, String> matchedMethods = new HashMap<>();

    private Map<Integer, Map<Integer, Integer>> apkCallerLists = new HashMap<>();

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

    private Map<Integer, Double> instruCount = new HashMap<>();;

    private Map<String, List<MethodSignature>> allTightSignatures;
    private Map<String, List<MethodSignature>> allLooseSignatures;

    public DatabaseMatcher(DatabaseMatcherParameters params, DatabaseReference ref) {
        this.params = params;
        this.ref = ref;
        sig = new Signature();
    }

    private void getSignatures(Signature sig) {
        allLooseSignatures = sig.getAllLooseSignatures();
        allTightSignatures = sig.getAllTightSignatures();
    }

    @Override
    public void storeMatchedClassesAndMethods(IDexUnit unit, DexHashcodeList dexHashCodeList, boolean firstRound) {

        if(firstRound) {
            // Load all signatures
            sig.loadAllSignatures(unit, ref);
        }

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
            if(applySignatures(unit, eClass, sig, dexHashCodeList, firstRound)) {
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

    //    private void getSignatures(Signature sig) {
    //        allLooseSignatures = sig.getAllLooseSignatures();
    //        allTightSignatures = sig.getAllTightSignatures();
    //    }

    private boolean applySignatures(IDexUnit dex, IDexClass eClass, Signature sig, DexHashcodeList dexHashCodeList,
            boolean firstRound) {
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
            if(instructions == null || instructions.size() <= params.methodSizeBar) {
                continue;
            }

            String mhash_tight = dexHashCodeList.getTightHashcode(eMethod);
            if(mhash_tight == null) {
                continue;
            }

            List<MethodSignature> elts = allTightSignatures.get(mhash_tight);

            if(elts != null && applySignatures_innerLoop(dex, sig, eMethod, elts, classPathCount, classPathMethod,
                    dupChecker, firstRound)) {
                flag = true;
            }
            else {
                String mhash_loose = dexHashCodeList.getLooseHashcode(eMethod);
                elts = allLooseSignatures.get(mhash_loose);
                if(elts != null && applySignatures_innerLoop(dex, sig, eMethod, elts, classPathCount, classPathMethod,
                        dupChecker, firstRound)) {
                    flag = true;
                }
            }
        }
        return flag;
    }

    private boolean applySignatures_innerLoop(IDexUnit dex, Signature sig, IDexMethod eMethod,
            List<MethodSignature> elts,
            Map<String, Integer> classPathCount_map, Map<String, Map<Integer, Set<String>>> classPathMethod_map,
            Set<String> dupChecker, boolean firstRound) {
        IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
        String shorty = proto.getShorty();
        String prototype = proto.generate(true);
        boolean flag = false;

        dupChecker.clear();

        if(firstRound) {
            // One class has several same sigs
            for(MethodSignature msig: elts) {
                String[] strArray = msig.toTokens();
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

            for(MethodSignature msig: elts) {
                String[] strArray = msig.toTokens();
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
                List<String[]> temp = map.get(count);
                if(temp != null) {
                    temp.add(strArray);
                }
                else {
                    ArrayList<String[]> temp1 = new ArrayList<>();
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
            uncertainMatchedClasses.put(eClass.getIndex(), new HashSet<>(classPathCandidates));
            return;
        }

        String classPath_sig_final = classPathCandidates.iterator().next();

        // Store methods
        ArrayList<Integer> temp1 = new ArrayList<>();
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
                    ArrayList<Integer> temp2 = new ArrayList<>();
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

        if(matchedInstrus / totalInstrus <= params.matchedInstusPercentageBar) {
            return false;
        }
        return true;
    }

    @Override
    public Map<Integer, String> postProcessRenameMethods(IDexUnit unit, DexHashcodeList dexHashCodeList,
            boolean firstRound) {
        return renameSmallMethods(unit, dexHashCodeList);
    }

    @Override
    public Map<Integer, String> postProcessRenameClasses(IDexUnit unit, DexHashcodeList dexHashCodeList,
            boolean firstRound) {
        return new HashMap<>();
    }

    private Map<Integer, String> renameSmallMethods(IDexUnit unit, DexHashcodeList dexHashCodeList) {
        Map<String, Integer> map = new HashMap<>();
        Map<Integer, String> newMatchedMethods = new HashMap<>();
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
                String mhash_tight = dexHashCodeList.getTightHashcode(method);
                if(mhash_tight == null) {
                    continue;
                }
                List<MethodSignature> sigs = allTightSignatures.get(mhash_tight);
                String methodName = null;
                if(sigs != null) {
                    methodName = findMethodName(map, treemap, sigs, shorty, classPath);
                }
                if(methodName == null) {
                    String mhash_loose = dexHashCodeList.getLooseHashcode(method);
                    sigs = allLooseSignatures.get(mhash_loose);
                    if(sigs != null) {
                        methodName = findMethodName(map, treemap, sigs, shorty, classPath);
                    }
                }
                if(methodName != null) {
                    newMatchedMethods.put(method.getIndex(), methodName);
                    matchedMethods.put(method.getIndex(), methodName);
                }
            }
        }
        return newMatchedMethods;
    }

    private String findMethodName(Map<String, Integer> map, TreeMap<Integer, ArrayList<String>> treemap,
            List<MethodSignature> sigs, String shorty, String classPath) {
        for(MethodSignature msig: sigs) {
            String[] strArray = msig.toTokens();
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

    /**
     * Get all matched classes.
     * 
     * @return a Map (key: index of a class. Value: a set of all matched classes(path))
     */
    @Override
    public Map<Integer, String> getMatchedClasses() {
        return matchedClasses;
    }

    /**
     * Get all matched methods.
     * 
     * @return a Map (Key: index of a method. Value: actual name of a method)
     */
    @Override
    public Map<Integer, String> getMatchedMethods() {
        return matchedMethods;
    }

    @Override
    public Map<Integer, Map<Integer, Integer>> getApkCallerLists() {
        return apkCallerLists;
    }

    @Override
    public DatabaseMatcherParameters getParameters() {
        return params;
    }

    @Override
    public ISignatureMetrics getSignatureMetrics() {
        return sig;
    }

}
