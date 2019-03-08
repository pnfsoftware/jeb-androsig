/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;
import java.util.TreeMap;

import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.DexHashcodeList;
import com.pnf.androsig.apply.model.LibraryInfo;
import com.pnf.androsig.apply.model.MethodSignature;
import com.pnf.androsig.apply.model.SignatureFile;
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
 * {@link #storeMatchedClassesAndMethods(IDexUnit, DexHashcodeList, boolean)} to perform analysis.
 * See {@link #getMatchedClasses()} and {@link #getMatchedMethods()} for results. This matcher
 * expects a class is replaced by a class (no cross changes). <br>
 * Note that contrary to v1 version which picks only one hashcode, this matcher uses a
 * {@link SignatureFile} per file, allowing to have a precise match, but it may consume more memry.
 * 
 * @author Cedric Lucas
 *
 */
class DatabaseMatcher2 implements IDatabaseMatcher, ISignatureMetrics {

    private DatabaseMatcherParameters params;
    private DatabaseReference ref;
    // class index --- classPath_sig
    private Map<Integer, String> matchedClasses = new HashMap<>();
    // method index --- methodName_sig
    private Map<Integer, String> matchedMethods = new HashMap<>();

    // private Map<Integer, Map<Integer, Integer>> apkCallerLists = new HashMap<>();

    // **** Rebuild structure ****
    // Check duplicate classes (if two or more classes match to the same library class, we need to avoid rename these classes)
    private Map<String, ArrayList<Integer>> dupClasses = new HashMap<>();
    // Check duplicate methods (same as dupClass)
    private Map<Integer, ArrayList<Integer>> dupMethods = new HashMap<>();

    private Set<String> usedSigFiles = new HashSet<>();

    private Map<Integer, Double> instruCount = new HashMap<>();;

    public DatabaseMatcher2(DatabaseMatcherParameters params, DatabaseReference ref) {
        this.params = params;
        this.ref = ref;
    }

    @Override
    public void storeMatchedClassesAndMethods(IDexUnit unit, DexHashcodeList dexHashCodeList, boolean firstRound) {
        List<? extends IDexClass> classes = unit.getClasses();
        if(classes == null || classes.size() == 0) {
            return;
        }
        for(IDexClass eClass: classes) {
            if(matchedClasses.containsKey(eClass.getIndex())) {
                continue;
            }
            // Get all candidates
            InnerMatch innerMatch = getClass(unit, eClass, dexHashCodeList, firstRound);
            if(innerMatch != null) {
                storeFinalCandidate(unit, eClass, innerMatch.className, innerMatch.classPathMethod);
            }
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
    }

    private InnerMatch getClass(IDexUnit dex, IDexClass eClass, DexHashcodeList dexHashCodeList, boolean firstRound) {
        List<? extends IDexMethod> methods = eClass.getMethods();
        if(methods == null || methods.size() == 0) {
            return null;
        }

        // First round: attempt to match class in its globality
        // Look for candidate files
        List<IDexMethod> smallMethods = new ArrayList<>();
        Map<String, Map<String, InnerMatch>> fileCandidates = new HashMap<>(); // file -> (classname->count)
        for(IDexMethod eMethod: methods) {
            if(!eMethod.isInternal() || matchedMethods.containsKey(eMethod.getIndex())) {
                continue;
            }

            // The second round
            //if(!firstRound && !apkCallerLists.containsKey(eMethod.getIndex())) {
            //    continue;
            //}

            List<? extends IInstruction> instructions = eMethod.getInstructions();
            if(instructions == null) {
                continue;
            }
            if(instructions.size() <= params.methodSizeBar) {
                smallMethods.add(eMethod);
                continue;
            }

            String mhash_tight = dexHashCodeList.getTightHashcode(eMethod);
            if(mhash_tight == null) {
                continue;
            }
            List<String> candidateFiles = ref.getFilesContainingTightHashcode(mhash_tight);
            if(candidateFiles != null) {
                for(String file: candidateFiles) {
                    List<String[]> sigLine = ref.getSignatureLines(file, mhash_tight, true);
                    Map<String, InnerMatch> classes = fileCandidates.get(file);
                    if(classes == null) {
                        classes = new HashMap<>();
                        fileCandidates.put(file, classes);
                    }
                    saveTemporaryCandidate(dex, eMethod, sigLine, firstRound, classes, file);
                }
            }
            else if(!firstRound) {
                // may be done even if tight is found
                String mhash_loose = dexHashCodeList.getLooseHashcode(eMethod);
                if(mhash_loose == null) {
                    continue;
                }
                candidateFiles = ref.getFilesContainingLooseHashcode(mhash_loose);
                if(candidateFiles != null) {
                    for(String file: candidateFiles) {
                        List<String[]> sigLine = ref.getSignatureLines(file, mhash_loose, false);
                        Map<String, InnerMatch> classes = fileCandidates.get(file);
                        if(classes == null) {
                            classes = new HashMap<>();
                            fileCandidates.put(file, classes);
                        }
                        saveTemporaryCandidate(dex, eMethod, sigLine, firstRound, classes, file);
                    }
                }
            }

        }

        // retrieve best candidates only
        Integer higherOccurence = 0;
        List<InnerMatch> bestCandidates = new ArrayList<>();
        for(Entry<String, Map<String, InnerMatch>> cand: fileCandidates.entrySet()) {
            higherOccurence = getBestCandidates(bestCandidates, cand.getValue().values(), higherOccurence);
        }
        if(bestCandidates.size() == 0) {
            return null;
        }

        //Find small methods
        for(InnerMatch cand: bestCandidates) {
            for(IDexMethod eMethod: methods) {
                String methodName = cand.classPathMethod.get(eMethod.getIndex());
                if(methodName != null) {
                    continue;
                }
                IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
                String shorty = dex.getStrings().get(proto.getShortyIndex()).getValue();
                String mhash_tight = dexHashCodeList.getTightHashcode(eMethod);
                if(mhash_tight == null) {
                    continue;
                }

                List<String[]> sigs = ref.getSignatureLines(cand.file, mhash_tight, true);
                if(sigs != null) {
                    methodName = findMethodName(sigs, shorty, cand.className);
                }
                if(methodName == null) {
                    String mhash_loose = dexHashCodeList.getLooseHashcode(eMethod);
                    sigs = ref.getSignatureLines(cand.file, mhash_loose, false);
                    if(sigs != null) {
                        methodName = findMethodName(sigs, shorty, cand.className);
                    }
                }
                if(methodName != null) {
                    cand.classPathMethod.put(eMethod.getIndex(), methodName);
                }
            }
        }
        InnerMatch bestCandidate = null;
        if(bestCandidates.size() == 1) {
            bestCandidate = bestCandidates.get(0);
        }
        else {
            higherOccurence = 0;
            for(Entry<String, Map<String, InnerMatch>> cand: fileCandidates.entrySet()) {
                higherOccurence = getBestCandidates(bestCandidates, cand.getValue().values(), higherOccurence);
            }
            if(bestCandidates.size() == 1) {
                bestCandidate = bestCandidates.get(0);
            }
            else {
                // TODO Test if methods are the same (can happen with different versions of same lib)
                // May be better to update DatabaseReference to load only once duplicated classes

                // Find total number of methods per class and compare with methods.size()
                TreeMap<Integer, List<InnerMatch>> diffMatch = new TreeMap<>();
                for(InnerMatch cand: bestCandidates) {
                    int methodCount = 0;
                    SignatureFile sig = ref.getSignatureFile(cand.file);
                    Collection<List<String[]>> allTight = sig.getAllTightSignatures().values();
                    for(List<String[]> tights: allTight) {
                        for(String[] tight: tights) {
                            if(MethodSignature.getClassname(tight).equals(cand.className)) {
                                methodCount++;
                            }
                        }
                    }
                    int diff = Math.abs(methods.size() - methodCount);
                    List<InnerMatch> newBestCandidates = diffMatch.get(diff);
                    if(newBestCandidates == null) {
                        newBestCandidates = new ArrayList<>();
                        diffMatch.put(diff, newBestCandidates);
                    }
                    newBestCandidates.add(cand);
                }
                bestCandidates = diffMatch.get(diffMatch.firstKey());

                // select one
                for(InnerMatch cand: bestCandidates) {
                    if(usedSigFiles.contains(cand.file)) {
                        // consider that same lib is used elsewhere == best chance
                        bestCandidate = cand;
                        break;
                    }
                }
                if(bestCandidate == null) {
                    bestCandidate = bestCandidates.get(0);
                }
            }
        }
        usedSigFiles.add(bestCandidate.file);
        return bestCandidate;
    }

    private static Integer getBestCandidates(List<InnerMatch> bestCandidates, Collection<InnerMatch> candidates,
            Integer higherOccurence) {
        for(InnerMatch candClass: candidates) {
            if(candClass.count > higherOccurence) {
                higherOccurence = candClass.count;
                bestCandidates.clear();
                bestCandidates.add(candClass);
            }
            else if(candClass.count == higherOccurence) {
                bestCandidates.add(candClass);
            }
        }
        return higherOccurence;
    }

    private static class InnerMatch {
        int count = 0;
        String className;
        Map<Integer, String> classPathMethod = new HashMap<>();
        String file;
    }

    private static void saveTemporaryCandidate(IDexUnit dex, IDexMethod eMethod, List<String[]> elts,
            boolean firstRound, Map<String, InnerMatch> classes, String file) {
        IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
        String shorty = proto.getShorty();
        String prototype = proto.generate(true);

        // One class has several same sigs
        for(String[] strArray: elts) {
            if(!MethodSignature.getShorty(strArray).equals(shorty)
                    || (firstRound && !MethodSignature.getPrototype(strArray).equals(prototype))) {
                continue;
            }
            String className = MethodSignature.getClassname(strArray);
            InnerMatch inner = classes.get(className);
            if(inner == null) {
                inner = new InnerMatch();
                inner.className = className;
                inner.file = file;
            }
            inner.count = inner.count + 1;
            inner.classPathMethod.put(eMethod.getIndex(), MethodSignature.getMethodName(strArray));
            classes.put(className, inner);
        }
    }

    private void storeFinalCandidate(IDexUnit unit, IDexClass eClass, String classPath_sig_final,
            Map<Integer, String> methodName_methods) {
        // Store methods
        ArrayList<Integer> temp1 = new ArrayList<>();
        if(methodName_methods == null || methodName_methods.size() == 0) {
            return;
        }
        for(Entry<Integer, String> methodName_method: methodName_methods.entrySet()) {
            temp1.add(methodName_method.getKey());
            matchedMethods.put(methodName_method.getKey(), methodName_method.getValue());
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

    private boolean f(IDexUnit unit, IDexClass eClass, List<Integer> matchedMethods) {
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
            if(methods.size() == 1) {
                // possible false positive: same constructor/super constructor only
                String name = methods.get(0).getName(true);
                if(name.equals("<init>") || name.equals("<clinit>")) {
                    return matchedInstrus > 20; // artificial metrics
                }
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
        return new HashMap<>();
    }

    @Override
    public Map<Integer, String> postProcessRenameClasses(IDexUnit unit, DexHashcodeList dexHashCodeList,
            boolean firstRound) {
        return new HashMap<>();
    }

    private String findMethodName(List<String[]> sigs, String shorty, String classPath) {
        Map<String, Integer> map = new HashMap<>();
        TreeMap<Integer, ArrayList<String>> treemap = new TreeMap<>(Collections.reverseOrder());
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
        return new HashMap<>();
    }

    @Override
    public DatabaseMatcherParameters getParameters() {
        return params;
    }

    @Override
    public ISignatureMetrics getSignatureMetrics() {
        return this;
    }

    @Override
    public int getAllSignatureCount() {
        int sigCount = 0;
        for(Entry<String, SignatureFile> sig: ref.getLoadedSignatureFiles().entrySet()) {
            if(usedSigFiles.contains(sig.getKey())) {
                sigCount += sig.getValue().getAllSignatureCount();
            }
        }
        return sigCount;
    }

    @Override
    public int getAllUsedSignatureFileCount() {
        return usedSigFiles.size();
    }

    @Override
    public Map<String, LibraryInfo> getAllLibraryInfos() {
        Map<String, LibraryInfo> libs = new HashMap<>();
        for(String usedSig: usedSigFiles) {
            libs.putAll(ref.getSignatureFile(usedSig).getAllLibraryInfos());
        }
        return libs;
    }

}
