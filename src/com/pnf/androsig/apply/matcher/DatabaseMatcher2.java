/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.stream.Collectors;

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
import com.pnfsoftware.jeb.util.base.JavaUtil;
import com.pnfsoftware.jeb.util.format.Strings;

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

    private static final String INVALID_MATCH = "INVALID";
    private DatabaseMatcherParameters params;
    private DatabaseReference ref;
    // class index --- classPath_sig
    private Map<Integer, String> matchedClasses = new HashMap<>();

    private Map<Integer, List<String>> matchedClassesFile = new HashMap<>();
    // method index --- methodName_sig
    private Map<Integer, String> matchedMethods = new HashMap<>();

    private Map<String, String> contextMatches = new HashMap<>();

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

        // Fully deterministic: select the best file or nothing: let populate usedSigFiles
        boolean processAll = true;
        for(IDexClass eClass: classes) {
            if(matchedClasses.containsKey(eClass.getIndex())) {
                continue;
            }
            // Get all candidates
            InnerMatch innerMatch = getClass(unit, eClass, dexHashCodeList, firstRound, true);
            if(innerMatch != null) {
                storeFinalCandidate(unit, eClass, innerMatch);
                processAll = false;
            }
        }

        if(!firstRound && processAll) {
            // more open: now allow to select one file amongst all matching
            for(IDexClass eClass: classes) {
                if(matchedClasses.containsKey(eClass.getIndex())) {
                    continue;
                }
                // Get all candidates
                InnerMatch innerMatch = getClass(unit, eClass, dexHashCodeList, firstRound, false);
                if(innerMatch != null) {
                    storeFinalCandidate(unit, eClass, innerMatch);
                }
            }
        }

        // expand: 
        for(Entry<String, String> entry: contextMatches.entrySet()) {
            if(entry.getValue().equals(INVALID_MATCH)) {
                continue;
            }
            IDexClass cl = unit.getClass(entry.getKey());
            if(cl != null) {
                matchedClasses.put(cl.getIndex(), entry.getValue());
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

    private InnerMatch getClass(IDexUnit dex, IDexClass eClass, DexHashcodeList dexHashCodeList, boolean firstRound,
            boolean unique) {
        List<? extends IDexMethod> methods = eClass.getMethods();
        if(methods == null || methods.size() == 0) {
            return null;
        }

        // First round: attempt to match class in its globality
        // Look for candidate files
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

        // Find small methods
        for(InnerMatch cand: bestCandidates) {
            for(IDexMethod eMethod: methods) {
                String[] strArray = cand.classPathMethod.get(eMethod.getIndex());
                if(strArray != null) {
                    continue;
                }
                IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
                String prototypes = proto.generate(true);
                String shorty = dex.getStrings().get(proto.getShortyIndex()).getValue();
                String mhash_tight = dexHashCodeList.getTightHashcode(eMethod);
                if(mhash_tight == null) {
                    continue;
                }

                List<String[]> sigs = ref.getSignatureLines(cand.file, mhash_tight, true);
                if(sigs != null) {
                    strArray = findMethodName(sigs, prototypes, shorty, cand.className, cand.classPathMethod.values());
                }
                if(strArray == null) {
                    String mhash_loose = dexHashCodeList.getLooseHashcode(eMethod);
                    sigs = ref.getSignatureLines(cand.file, mhash_loose, false);
                    if(sigs != null) {
                        strArray = findMethodName(sigs, prototypes, shorty, cand.className,
                                cand.classPathMethod.values());
                    }
                }
                if(strArray != null) {
                    cand.classPathMethod.put(eMethod.getIndex(), strArray);
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

                if(bestCandidates.size() == 1) {
                    bestCandidate = bestCandidates.get(0);
                }
                else if(firstRound || unique) {
                    return null;
                }
                else {
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
        }
        usedSigFiles.add(bestCandidate.file);
        matchedClassesFile.put(eClass.getIndex(),
                bestCandidates.stream().map(c -> c.file).collect(Collectors.toList()));
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
        Map<Integer, String[]> classPathMethod = new HashMap<>();
        String file;
        List<Integer> doNotRenameIndexes = new ArrayList<>();
    }

    private static void saveTemporaryCandidate(IDexUnit dex, IDexMethod eMethod, List<String[]> elts,
            boolean firstRound, Map<String, InnerMatch> classes, String file) {
        IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
        String shorty = proto.getShorty();
        String prototype = proto.generate(true);

        // One class has several same sigs
        List<String[]> realCandidates = elts.stream()
                .filter(strArray -> MethodSignature.getShorty(strArray).equals(shorty)
                && MethodSignature.getPrototype(strArray).equals(prototype)).collect(Collectors.toList());
        if(!realCandidates.isEmpty()) {
            String[] strArray = realCandidates.get(0);
            String className = MethodSignature.getClassname(strArray);
            InnerMatch inner = classes.get(className);
            if(inner == null) {
                inner = new InnerMatch();
                inner.className = className;
                inner.file = file;
            }
            inner.count = inner.count + 1;
            inner.classPathMethod.put(eMethod.getIndex(), strArray);
            if(realCandidates.size() > 1) {
                // we can not establish which method is the good one
                // however, it is good to report that a matching was found (for percentage matching instructions
                inner.doNotRenameIndexes.add(eMethod.getIndex());
            }
            classes.put(className, inner);
        }
    }

    private void storeFinalCandidate(IDexUnit unit, IDexClass eClass, InnerMatch innerMatch) {
        // Store methods
        ArrayList<Integer> temp1 = new ArrayList<>();
        if(innerMatch.classPathMethod == null || innerMatch.classPathMethod.size() == 0) {
            return;
        }
        for(Entry<Integer, String[]> methodName_method: innerMatch.classPathMethod.entrySet()) {
            temp1.add(methodName_method.getKey());
            if(!innerMatch.doNotRenameIndexes.contains(methodName_method.getKey())) {
                matchedMethods.put(methodName_method.getKey(),
                        MethodSignature.getMethodName(methodName_method.getValue()));
            }
        }

        if(temp1.size() != 0) {
            if(f(unit, eClass, temp1)) {
                matchedClasses.put(eClass.getIndex(), innerMatch.className);
                ArrayList<Integer> tempArrayList = dupClasses.get(innerMatch.className);
                if(tempArrayList != null) {
                    tempArrayList.add(eClass.getIndex());
                    dupClasses.put(innerMatch.className, tempArrayList);
                }
                else {
                    ArrayList<Integer> temp2 = new ArrayList<>();
                    temp2.add(eClass.getIndex());
                    dupClasses.put(innerMatch.className, temp2);
                }
                dupMethods.put(eClass.getIndex(), temp1);

                // postprocess: reinject class
                for(Entry<Integer, String[]> methodName_method: innerMatch.classPathMethod.entrySet()) {
                    IDexMethod m = unit.getMethod(methodName_method.getKey());
                    IDexPrototype proto = unit.getPrototypes().get(m.getPrototypeIndex());
                    String prototypes = proto.generate(true);
                    String[] strArray = methodName_method.getValue();
                    if(prototypes.equals(MethodSignature.getPrototype(strArray))) {
                        continue;
                    }
                    saveParamMatching(prototypes, MethodSignature.getPrototype(strArray));
                }
            }
            else {
                for(int e: temp1) {
                    matchedMethods.remove(e);
                }
            }
        }
    }

    private void saveParamMatching(String oldProto, String newProto) {
        // extract return type
        String[] tokens1 = oldProto.substring(1).split("\\)");
        String[] tokens2 = newProto.substring(1).split("\\)");
        if(tokens1.length != 2 || tokens2.length != 2) {
            return;
        }
        List<String> oldClasses = parseSignatureParameters(tokens1[0]);
        oldClasses.add(tokens1[1]);
        List<String> newClasses = parseSignatureParameters(tokens2[0]);
        newClasses.add(tokens2[1]);
        if(oldClasses.size() != newClasses.size()) {
            // parameter non use removed? too risky
            return;
        }
        for(int i = 0; i < oldClasses.size(); i++) {
            String oldClass = oldClasses.get(i);
            String newClass = newClasses.get(i);
            if(!oldClass.equals(newClass) && oldClass.endsWith(";")) {
                // return value updated
                while(oldClass.charAt(0) == '[') {
                    if(newClass.charAt(0) != '[') {
                        // argument swaps?
                        return;
                    }
                    oldClass = oldClass.substring(1);
                    newClass = newClass.substring(1);
                }
                while(newClass.contains("$") && oldClass.contains("$")) {
                    int lastIndex = newClass.lastIndexOf('$');
                    String newClassName = newClass.substring(newClass.lastIndexOf('$'));
                    if (!oldClass.endsWith(newClassName)) {
                        saveMatch(oldClass, newClass);
                    }
                    oldClass = oldClass.substring(0, oldClass.lastIndexOf("$")) + ";";
                    newClass = newClass.substring(0, lastIndex) + ";";
                }
                if(!oldClass.equals(newClass)) {
                    saveMatch(oldClass, newClass);
                }
            }
        }
    }

    private void saveMatch(String oldClass, String newClass) {
        String value = contextMatches.get(oldClass);
        if(value != null) {
            if(value.equals(INVALID_MATCH)) {
                return;
            }
            else if(!value.equals(newClass)) {
                contextMatches.put(oldClass, INVALID_MATCH);
                return;
            }
        }
        contextMatches.put(oldClass, newClass);
    }

    private static List<String> parseSignatureParameters(String parameters) {
        List<String> params = new ArrayList<>();
        int i = 0;
        while(i < parameters.length()) {
            int begin = i;
            while(parameters.charAt(i) == '[') {
                i++;
            }
            char type = parameters.charAt(i);
            if(type == 'L') {
                int end = parameters.indexOf(';', i);
                if(end < 0) {
                    // invalid sig
                    return null;
                }
                params.add(parameters.substring(begin, end + 1));
                i = end + 1;
            }
            else if(JavaUtil.letterToPrimitive(type + "") != null) {
                params.add(parameters.substring(begin, i + 1));
                i++;
            }
            else {
                // invalid param
                return null;
            }
        }
        return params;
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
    public Map<Integer, String> postProcessRenameClasses(IDexUnit dex, DexHashcodeList dexHashCodeList,
            boolean firstRound) {
        // maybe more parameter matches for method signatures (where only shorty matched previously)
        for(Entry<Integer, String> entry: matchedClasses.entrySet()) {
            IDexClass eClass = dex.getClass(entry.getKey());
            if(eClass == null) {
                continue;
            }
            List<? extends IDexMethod> methods = eClass.getMethods();
            if(methods == null || methods.size() == 0) {
                return null;
            }
            String className = eClass.getSignature(true);
            List<String[]> alreadyMatches = new ArrayList<>(); // TODO fill

            //
            for(IDexMethod eMethod: methods) {
                if(!eMethod.isInternal() || matchedMethods.containsKey(eMethod.getIndex())) {
                    continue;
                }

                IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
                String prototypes = proto.generate(true);
                String shorty = dex.getStrings().get(proto.getShortyIndex()).getValue();
                String mhash_tight = dexHashCodeList.getTightHashcode(eMethod);
                if(mhash_tight == null) {
                    continue;
                }

                List<String> files = matchedClassesFile.get(entry.getKey());
                if(files == null) {
                    files = ref.getFilesContainingClass(className);
                    if(files == null) {
                        // external library (not in signature files)
                        continue;
                    }
                }
                String methodName = "";
                String[] strArray = null;
                for(String file: files) {
                    List<String[]> sigs = ref.getSignatureLines(file, mhash_tight, true);
                    if(sigs != null) {
                        strArray = findMethodName(sigs, prototypes, shorty, className, alreadyMatches);
                    }
                    if(strArray == null) {
                        String mhash_loose = dexHashCodeList.getLooseHashcode(eMethod);
                        sigs = ref.getSignatureLines(file, mhash_loose, false);
                        if(sigs != null) {
                            strArray = findMethodName(sigs, prototypes, shorty, className, alreadyMatches);
                        }
                    }
                    if(strArray != null) {
                        String newMethodName = MethodSignature.getMethodName(strArray);
                        if(methodName.isEmpty()) {
                            methodName = newMethodName;
                        }
                        else if(!methodName.equals(newMethodName)) {
                            methodName = null;
                            break;
                        }
                    }
                    else {
                        methodName = null;
                        break;
                    }
                }
                if(!Strings.isBlank(methodName) && !eMethod.getName(true).equals(methodName)) {
                    matchedMethods.put(eMethod.getIndex(), methodName);

                    // postprocess: reinject class
                    if(!prototypes.equals(MethodSignature.getPrototype(strArray))) {
                        saveParamMatching(prototypes, MethodSignature.getPrototype(strArray));
                    }
                }
            }
        }
        return new HashMap<>();
    }

    private String[] findMethodName(List<String[]> sigs, String proto, String shorty, String classPath,
            Collection<String[]> methods) {
        List<String[]> results = new ArrayList<>();
        proto: for(String[] strArray: sigs) {
            if(!MethodSignature.getPrototype(strArray).equals(proto)) {
                continue;
            }
            if(!MethodSignature.getClassname(strArray).equals(classPath)) {
                continue;
            }
            for(String[] alreadyProcessed: methods) {
                if(MethodSignature.getPrototype(alreadyProcessed).equals(MethodSignature.getPrototype(strArray))
                        && MethodSignature.getMethodName(alreadyProcessed)
                                .equals(MethodSignature.getMethodName(strArray))) {
                    // method has already a match
                    continue proto;
                }
            }
            results.add(strArray);
        }
        if(results.size() == 1) {
            return results.get(0);
        }
        else if(results.size() > 1) {
            return null;
        }
        for(String[] strArray: sigs) {
            if(!MethodSignature.getShorty(strArray).equals(shorty)) {
                continue;
            }
            if(!MethodSignature.getClassname(strArray).equals(classPath)) {
                continue;
            }
            results.add(strArray);
        }
        if(results.size() == 1) {
            return results.get(0);
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
