/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import com.pnf.androsig.apply.matcher.MatchingSearch.InnerMatch;
import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.DexHashcodeList;
import com.pnf.androsig.apply.model.ISignatureFile;
import com.pnf.androsig.apply.model.LibraryInfo;
import com.pnf.androsig.apply.model.MethodSignature;
import com.pnf.androsig.apply.modules.ApkCallerModule;
import com.pnf.androsig.apply.modules.ReverseMatchingModule;
import com.pnf.androsig.apply.util.DexUtilLocal;
import com.pnfsoftware.jeb.core.units.code.ICodeType;
import com.pnfsoftware.jeb.core.units.code.IInstruction;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexCodeItem;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethodData;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexPrototype;
import com.pnfsoftware.jeb.util.format.Strings;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * Aims at building the matched classes and signature in a {@link IDexUnit}. No modification is made
 * on {@link IDexUnit}, the purpose of this class is only to find matches. Call
 * {@link #storeMatchedClassesAndMethods(IDexUnit, DexHashcodeList, boolean)} to perform analysis.
 * See {@link #getMatchedClasses()} and {@link #getMatchedMethods()} for results. This matcher
 * expects a class is replaced by a class (no cross changes). <br>
 * Note that contrary to v1 version which picks only one hashcode, this matcher uses a
 * {@link ISignatureFile} per file, allowing to have a precise match, but it may consume more
 * memory.
 * 
 * <p>
 * In details, there are several important structures:
 * <li>{@link #matchedClasses} and {@link #matchedMethods} that are the final matches exposed to
 * caller</li>
 * <li>{@link #contextMatches} that is populated when context found something fuzzy (a class name
 * match, a method name), but not from signature directly. This context is injected to
 * {@link #matchedClasses} and {@link #matchedMethods} when other processing is stable enough.</li>
 * <li>{@link DatabaseReference} keeps a reference of all signature files.</li>
 * <li>{@link FileMatches} keeps a bound to signature file that was used to determine a particular
 * class</li>
 * 
 * <p>
 * and several important methods:
 * <li>{@link #storeMatchedClassesAndMethods(IDexUnit, DexHashcodeList, boolean)} search through all
 * classes for signature matching of its methods and attempt to find a valid class. If found, the
 * matched class and matched methods are <b>saved</b>. Then, it loops over classes and method
 * matches that has been found previously by context (for example classes that were found by
 * determining arguments of methods previously matched). This method populates the
 * {@link #getMatchedClasses()} and {@link #getMatchedMethods()} for future renaming.</li>
 * <li>{@link #postProcessRenameClasses(IDexUnit, DexHashcodeList, boolean)} must be called after a
 * renaming is performed. It will loop over all renamed classes to attempt a match on missed
 * methods. It may also update context by method arguments</li>
 * <li>{@link #postProcessRenameMethods(IDexUnit, DexHashcodeList, boolean)} must be called after a
 * renaming is performed. It will loop over method signatures to try to determine its callers (the
 * caller data will be saved to context).</li>
 * 
 * @author Cedric Lucas
 *
 */
class DatabaseMatcher2 implements IDatabaseMatcher, ISignatureMetrics, IMatcherValidation {
    private final ILogger logger = GlobalLog.getLogger(DatabaseMatcher2.class);

    private DatabaseMatcherParameters params;
    private DatabaseReference ref;
    // class index --- classPath_sig
    private Map<Integer, String> matchedClasses = new LinkedHashMap<>();
    private Set<Integer> ignoredClasses = new HashSet<>();

    // method index --- methodName_sig
    private Map<Integer, String> matchedMethods = new LinkedHashMap<>();
    private Map<Integer, MethodSignature> matchedSigMethods = new HashMap<>();

    private ContextMatches contextMatches = new ContextMatches();

    private FileMatches fileMatches = new FileMatches();

    // **** Rebuild structure ****
    // Check duplicate classes (if two or more classes match to the same library class, we need to avoid rename these classes)
    private Map<String, ArrayList<Integer>> dupClasses = new HashMap<>();
    // Check duplicate methods (same as dupClass)
    private Map<Integer, ArrayList<Integer>> dupMethods = new HashMap<>();

    private Map<Integer, Double> instruCount = new HashMap<>();

    private List<IAndrosigModule> modules = new ArrayList<>();

    public DatabaseMatcher2(DatabaseMatcherParameters params, DatabaseReference ref) {
        this.params = params;
        this.ref = ref;
        if(params.useCallerList) {
            modules.add(new ApkCallerModule(this, contextMatches, fileMatches, ref, matchedSigMethods));
        }
        if(params.useReverseMatching) {
            modules.add(new ReverseMatchingModule(this, contextMatches, fileMatches, ref, params, modules));
        }
    }

    private void addMatchedClass(IDexClass cl, String classname, boolean safe) {
        if(matchedClasses.get(cl.getIndex()) != null) {
            logger.error("Conflict: Try to replace class %s", matchedClasses.get(cl.getIndex()));
            return;
        }
        if(matchedClasses.containsValue(classname)) {
            logger.error("Conflict: Try to bind class %s to %s which is already bind to ", classname,
                    cl.getSignature(false), cl.getSignature(true));
            return;
        }
        matchedClasses.put(cl.getIndex(), classname);
        if(!safe) {
            fileMatches.removeClassFiles(cl);
        }
    }

    @Override
    public void storeMatchedClassesAndMethods(IDexUnit unit, DexHashcodeList dexHashCodeList, boolean firstRound) {
        for(IAndrosigModule module: modules) {
            module.initNewPass(unit, dexHashCodeList, firstRound);
        }
        List<IDexClass> sortedClasses = DexUtilLocal.getSortedClasses(unit);
        if(sortedClasses == null) {
            return;
        }

        if(firstRound) {
            // clean up classes which have same name
            bindUnrenamedClasses(unit, sortedClasses, dexHashCodeList);
        }

        // Fully deterministic: select the best file or nothing: let populate usedSigFiles
        boolean processSecondPass = storeFinalCandidates(unit, sortedClasses, dexHashCodeList, firstRound, true);

        if(!firstRound && processSecondPass) {
            // more open: now allow to select one file amongst all matching
            storeFinalCandidates(unit, sortedClasses, dexHashCodeList, firstRound, false);
        }

        // expand: Add classes and methods found by context (method signature, caller)
        for(Entry<String, String> entry: contextMatches.entrySet()) {
            if(!contextMatches.isValid(entry.getValue())) {
                continue;
            }
            IDexClass cl = unit.getClass(entry.getKey());
            if(cl != null) {
                String newName = matchedClasses.get(cl.getIndex());
                if(newName == null) {
                    addMatchedClass(cl, entry.getValue(), false);
                }
                else if(!newName.equals(entry.getValue())) {
                    logger.warn("Conflict for class: Class %s was already renamed to %s. Can not rename to %s",
                            cl.getName(false), newName, entry.getValue());
                    contextMatches.setInvalidClass(entry.getKey());
                }
            }
        }
        for(Entry<Integer, String> entry: contextMatches.methodsEntrySet()) {
            if(!contextMatches.isValid(entry.getValue())) {
                continue;
            }
            String newName = matchedMethods.get(entry.getKey());
            IDexMethod m = unit.getMethod(entry.getKey());
            if(newName == null) {
                matchedMethods.put(entry.getKey(), entry.getValue());
            }
            else if(!newName.equals(entry.getValue())) {
                logger.warn("Conflict for method: Method %s was already renamed to %s. Can not rename to %s",
                        m.getName(false), newName, entry.getValue());
                contextMatches.setInvalidMethod(entry.getKey());
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
                        matchedSigMethods.remove(eMethod);
                    }
                }
            }
        }
        // GC
        dupClasses.clear();
        dupMethods.clear();
    }

    private void bindUnrenamedClasses(IDexUnit dex, List<IDexClass> classes, DexHashcodeList dexHashCodeList) {
        for(IDexClass eClass: classes) {
            String originalSignature = eClass.getSignature(true);
            List<String> files = ref.getFilesContainingClass(originalSignature);
            if(files == null) {
                continue;
            }
            List<? extends IDexMethod> methods = eClass.getMethods();
            if(methods == null || methods.size() == 0) {
                // since signature only contains non empty classes, there is no chance that we found by matching
                continue;
            }

            MatchingSearch fileCandidates = new MatchingSearch(dex, dexHashCodeList, ref, params, fileMatches,
                    modules, true, true);
            int innerLevel = DexUtilLocal.getInnerClassLevel(originalSignature);
            fileCandidates.processClass(this, matchedMethods, eClass, methods, innerLevel, files);

            filterVersions(fileCandidates);

            List<InnerMatch> candidates = new ArrayList<>();
            for(Entry<String, Map<String, InnerMatch>> entry: fileCandidates.entrySet()) {
                for(Entry<String, InnerMatch> entry2: entry.getValue().entrySet()) {
                    if(entry2.getKey().equals(originalSignature)) {
                        candidates.add(entry2.getValue());
                    }
                }
            }
            if(candidates.size() == 1) {
                InnerMatch innerMatch = candidates.get(0);
                addMatchedClass(eClass, innerMatch.className, false);
                fileMatches.addVersions(innerMatch.file, innerMatch.classPathMethod.values());
            }
            else {
                fileCandidates = new MatchingSearch(dex, dexHashCodeList, ref, params, fileMatches, modules,
                        false, true);
                innerLevel = DexUtilLocal.getInnerClassLevel(originalSignature);
                fileCandidates.processClass(this, matchedMethods, eClass, methods, innerLevel, files);

                filterVersions(fileCandidates);
                candidates = new ArrayList<>();
            }
        }
    }

    private boolean storeFinalCandidates(IDexUnit unit, List<? extends IDexClass> classes,
            DexHashcodeList dexHashCodeList, boolean firstRound, boolean firstPass) {
        boolean found = false;
        for(IDexClass eClass: classes) {
            if(matchedClasses.containsKey(eClass.getIndex())) {
                continue;
            }
            // Get all candidates
            InnerMatch innerMatch = getClass(unit, eClass, dexHashCodeList, firstRound, firstPass);
            if(innerMatch != null) {
                if(storeFinalCandidate(unit, eClass, innerMatch, firstRound)) {
                    fileMatches.addMatchedClassFiles(eClass, innerMatch.file);
                    found = true;
                }
            }
        }
        return found;
    }

    /**
     * Retrieve the best class candidate regarding context (method hash matching, signature
     * matching...). The candidate may be poor (with a low coverage volume) and must be validated
     * afterward.
     */
    protected InnerMatch getClass(IDexUnit dex, IDexClass eClass, DexHashcodeList dexHashCodeList, boolean firstRound,
            boolean unique) {
        List<? extends IDexMethod> methods = eClass.getMethods();
        if(methods == null || methods.size() == 0) {
            // since signature only contains non empty classes, there is no chance that we found by matching
            return null;
        }

        MatchingSearch fileCandidates = new MatchingSearch(dex, dexHashCodeList, ref, params, fileMatches,
                modules, firstRound, unique);
        String originalSignature = eClass.getSignature(true);
        int innerLevel = DexUtilLocal.getInnerClassLevel(originalSignature);
        boolean parentClassFound = false;
        if(DexUtilLocal.isInnerClass(originalSignature)) {
            IDexClass parentClass = DexUtilLocal.getParentClass(dex, originalSignature);
            String name = parentClass == null ? null: matchedClasses.get(parentClass.getIndex());
            if(name != null) {
                parentClassFound = true;
                // parent class mapping found: what are the inner class defined for?
                DatabaseReferenceFile file = fileMatches.getFileFromClass(parentClass);
                if(file != null) {
                    // Retrieve all inner class belonging to parent
                    String innerClass = name.substring(0, name.length() - 1) + "$";
                    List<MethodSignature> compatibleSignatures = ref.getSignaturesForClassname(file, innerClass, false);

                    // is there only one class that can match? TODO version filter?
                    List<MethodSignature> candidates = MatchingSearch.mergeSignaturesPerClass(compatibleSignatures);
                    Set<String> versions = null;
                    candidates = filterVersions(candidates, versions);
                    candidates = candidates.stream()
                            .filter(inner -> isInnerClassCandidate(dex, inner, eClass, innerLevel))
                            .collect(Collectors.toList());
                    if(candidates.size() == 1) {
                        // bypass f validation
                        contextMatches.saveClassMatch(originalSignature, candidates.get(0).getCname(), name);
                        return null;
                    }


                    compatibleSignatures = compatibleSignatures.stream()
                            .filter(inner -> isInnerClassCandidate(dex, inner, eClass, innerLevel))
                            .collect(Collectors.toList());
                    compatibleSignatures = filterVersions(compatibleSignatures, versions);
                    fileCandidates.processInnerClass(file.file, matchedMethods, methods, innerClass, innerLevel,
                            compatibleSignatures);
                    ignoredClasses.remove(eClass.getIndex());
                }
                else {
                    //System.out.println("No reference file for " + parentSignature);
                }
            }
            else {
                // Inner class, in general are more or less like a method (in terms of data match), so wait for parent to be matched before analysis
                if(firstRound || unique) {
                    return null;
                }
            }
        }

        if(ignoredClasses.contains(eClass.getIndex())) {
            return null;
        }
        // First round: attempt to match class in its globality
        // Look for candidate files
        boolean hasCandidates = true;
        if(fileCandidates.isEmpty()) {
            hasCandidates = fileCandidates.processClass(this, matchedMethods, eClass, methods, innerLevel);
            if(!hasCandidates) {
                ignoredClasses.add(eClass.getIndex());
            }
        }

        if(fileCandidates.isEmpty()) {
            return null;
        }

        filterVersions(fileCandidates);

        findSmallMethods(fileCandidates, originalSignature, methods, unique);

        List<InnerMatch> bestCandidates = filterMaxMethodsMatch(fileCandidates);

        InnerMatch bestCandidate = null;
        if(bestCandidates.isEmpty()) {
            return null;
        }
        else if(bestCandidates.size() == 1) {
            bestCandidate = bestCandidates.get(0);
        }
        else {
            // Find total number of methods per class and compare with methods.size()
            TreeMap<Integer, Set<InnerMatch>> diffMatch = new TreeMap<>();
            for(InnerMatch cand: bestCandidates) {
                Map<String, Integer> methodCountPerVersion = new HashMap<>();
                List<MethodSignature> allTight = ref.getSignaturesForClassname(cand.file, cand.className, true);
                for(MethodSignature tight: allTight) {
                    String[] versions = tight.getVersions();
                    if(versions == null) {
                        DatabaseReferenceFile.increment(methodCountPerVersion, "all");
                    }
                    else {
                        for(String v: versions) {
                            DatabaseReferenceFile.increment(methodCountPerVersion, v);
                        }
                    }
                }
                for(Integer methodCount: methodCountPerVersion.values()) {
                    int diff = Math.abs(methods.size() - methodCount);
                    Set<InnerMatch> newBestCandidates = diffMatch.get(diff);
                    if(newBestCandidates == null) {
                        newBestCandidates = new HashSet<>();
                        diffMatch.put(diff, newBestCandidates);
                    }
                    newBestCandidates.add(cand);
                }
            }
            bestCandidates = new ArrayList<>(diffMatch.get(diffMatch.firstKey()));

            if(bestCandidates.size() == 1) {
                bestCandidate = bestCandidates.get(0);
            }
            else {
                if(!firstRound) {
                    String className = null;
                    for(InnerMatch cand: bestCandidates) {
                        if(className == null) {
                            className = cand.className;
                        }
                        else if(!className.equals(cand.className)) {
                            className = null;
                            break;
                        }
                    }
                    if(className != null) {
                        // same classname (can happen with different versions of same lib)
                        String bestFile = fileMatches.getMatchedClassFile(eClass, className, ref);
                        if(bestFile != null) {
                            for(InnerMatch cand: bestCandidates) {
                                if(cand.file.equals(bestFile)) {
                                    bestCandidate = cand;
                                    break;
                                }
                            }
                        }
                    }
                }
                // too much error-prone: must at least found same classname
                if(bestCandidate == null) {
                    return null;
                }
            }
        }
        if(bestCandidate.oneMatch) {
            if(DexUtilLocal.isInnerClass(originalSignature) && !parentClassFound) {
                return null;
            }
            // seriously check matching class: may be a false positive
            List<MethodSignature> allMethods = ref.getSignaturesForClassname(bestCandidate.file,
                    bestCandidate.className, true);
            allMethods = filterVersions(allMethods, bestCandidate.versions);
            Set<String> methodNames = allMethods.stream().map(m -> m.getMname() + m.getPrototype())
                    .collect(Collectors.toSet());
            if(methodNames.size() != bestCandidate.classPathMethod.size()) {
                // false positive most of the time: may investigate more here
                // expect to find match by param matching, safer
                return null;
            }
        }
        return bestCandidate;
    }

    private void filterVersions(MatchingSearch fileCandidates) {
        // here, we clean up the methods which don't belong to same version
        for(Entry<String, Map<String, InnerMatch>> entry: fileCandidates.entrySet()) {
            for(InnerMatch cand: entry.getValue().values()) {
                cand.validateVersions();
                if(cand.classPathMethod.size() == 1) {
                    // one method match can be luck match: validate other methods with signature exists
                    cand.oneMatch = true;
                }
            }
        }
    }

    private void findSmallMethods(MatchingSearch fileCandidates, String originalSignature,
            List<? extends IDexMethod> methods, boolean firstPass) {
        // Find small methods
        for(Entry<String, Map<String, InnerMatch>> entry: fileCandidates.entrySet()) {
            for(InnerMatch cand: entry.getValue().values()) {
                if(cand.oneMatch || DexUtilLocal.isInnerClass(originalSignature)) {
                    // do not artificially grow easy matches, unless file is in use
                    if(!this.fileMatches.isSignatureFileUsed(cand.file)) {
                        continue;
                    }
                }
                List<MethodSignature> sigs = null;
                for(IDexMethod eMethod: methods) {
                    MethodSignature strArray = cand.classPathMethod.get(eMethod.getIndex());
                    if(strArray != null) {
                        continue;
                    }
                    strArray = fileCandidates.findMethodMatch(cand.file, cand.className, cand.classPathMethod.values(),
                            eMethod, true);
                    if(strArray != null) {
                        cand.classPathMethod.put(eMethod.getIndex(), strArray);
                    }
                    else if(!firstPass && !cand.oneMatch) {
                        if(sigs == null) {
                            // lazy init
                            sigs = ref.getSignaturesForClassname(cand.file, cand.className, true);
                        }
                        strArray = fileCandidates.findMethodName(sigs, cand.className, new ArrayList<>(), eMethod);
                        if(strArray != null && strArray.getMname() != null && strArray.getPrototype() != null) {
                            cand.classPathMethod.put(eMethod.getIndex(), strArray);
                        }
                    }
                }
            }
        }
    }

    private boolean isInnerClassCandidate(IDexUnit dex, MethodSignature inner, IDexClass eClass, int innerLevel) {
        IDexClass innerCl = dex.getClass(inner.getCname());
        // remove classes that already matched
        if(innerCl != null && matchedClasses.containsKey(innerCl.getIndex())) {
            return false;
        }
        if(DexUtilLocal.isAnonymous(eClass) != DexUtilLocal.isAnonymous(inner.getCname())) {
            return false;
        }
        if(innerLevel != DexUtilLocal.getInnerClassLevel(inner.getCname())) {
            return false;
        }
        return true;
    }

    private List<MethodSignature> filterVersions(List<MethodSignature> candidates, Set<String> versions) {
        if(versions == null) {
            return candidates;
        }
        List<MethodSignature> newCandidates = new ArrayList<>();
        for(MethodSignature cand: candidates) {
            for(String v: versions) {
                String[] versionsArray = cand.getVersions();
                if(versionsArray == null) {
                    return candidates;
                }
                if(Arrays.asList(versionsArray).contains(v)) {
                    newCandidates.add(cand);
                    break;
                }
            }
        }
        return newCandidates;
    }

    private static List<InnerMatch> filterMaxMethodsMatch(MatchingSearch fileCandidates) {
        Integer higherOccurence = 0;
        List<InnerMatch> bestCandidates = new ArrayList<>();
        for(Entry<String, Map<String, InnerMatch>> cand: fileCandidates.entrySet()) {
            higherOccurence = getBestCandidatesInner(bestCandidates, cand.getValue().values(), higherOccurence);
        }
        return bestCandidates;
    }

    private static Integer getBestCandidatesInner(List<InnerMatch> bestCandidates, Collection<InnerMatch> candidates,
            Integer higherOccurence) {
        for(InnerMatch candClass: candidates) {
            if(candClass.classPathMethod.size() > higherOccurence) {
                higherOccurence = candClass.classPathMethod.size();
                bestCandidates.clear();
                bestCandidates.add(candClass);
            }
            else if(candClass.classPathMethod.size() == higherOccurence) {
                bestCandidates.add(candClass);
            }
        }
        return higherOccurence;
    }



    /**
     * Validate a candidate match and save it.
     */
    protected boolean storeFinalCandidate(IDexUnit unit, IDexClass eClass, InnerMatch innerMatch, boolean firstRound) {
        if(innerMatch.className.contains("$")) {
            // allow renaming only when parent classes are fine, because inner class tend to be the same in some projects
            String originalSignature = eClass.getSignature(true);
            if(!originalSignature.contains("$")) {
                // inner class match a non inner class => dangerous
                fileMatches.removeClassFiles(eClass);
                return false;
            }
            String parentSignature = originalSignature.substring(0, originalSignature.lastIndexOf("$")) + ";";
            String parentMatchSignature = innerMatch.className.substring(0, innerMatch.className.lastIndexOf("$"))
                    + ";";
            if(!parentSignature.equals(parentMatchSignature)) {
                // expect parent match: otherwise, wait for parent match
                if(firstRound) {
                    fileMatches.removeClassFiles(eClass);
                    return false;
                }
                else {
                    String oldClass = eClass.getSignature(true);
                    String newClass = innerMatch.className;
                    // Preprocess: if new class is already renamed, there is no reason to move another one
                    String oldParentClass = oldClass;
                    String newParentClass = newClass;
                    while(newParentClass.contains("$") && oldParentClass.contains("$")) {
                        oldParentClass = oldParentClass.substring(0, oldParentClass.lastIndexOf("$")) + ";";
                        newParentClass = newParentClass.substring(0, newParentClass.lastIndexOf("$")) + ";";
                        IDexClass oldParentClassObj = unit.getClass(oldParentClass);
                        if(oldParentClassObj == null) {
                            continue;
                        }
                        int oldClassId = oldParentClassObj.getIndex();
                        IDexClass newParentClassObj = unit.getClass(newParentClass);
                        String oldParentMatch = matchedClasses.get(oldClassId);
                        if(oldParentMatch != null) {
                            // parent class has already a match: must be the same
                            if(!oldParentMatch.equals(newParentClass)) {
                                fileMatches.removeClassFiles(eClass);
                                return false;
                            }
                        }
                        else if(newParentClassObj != null && matchedClasses.get(newParentClassObj.getIndex()) != null) {
                            // destination class is being/has been renamed but does not match the original class
                            fileMatches.removeClassFiles(eClass);
                            return false;
                        }
                    }
                    while(newClass.contains("$") && oldClass.contains("$")) {
                        int lastIndex = newClass.lastIndexOf('$');
                        String newClassName = newClass.substring(newClass.lastIndexOf('$'));
                        if(!oldClass.endsWith(newClassName)) {
                            contextMatches.saveClassMatch(oldClass, newClass, innerMatch.className);
                        }
                        oldClass = oldClass.substring(0, oldClass.lastIndexOf("$")) + ";";
                        newClass = newClass.substring(0, lastIndex) + ";";
                    }
                }
            }
        }
        // Store methods
        ArrayList<Integer> temp1 = new ArrayList<>();
        if(innerMatch.classPathMethod == null || innerMatch.classPathMethod.size() == 0) {
            return false;
        }
        for(Entry<Integer, MethodSignature> methodName_method: innerMatch.classPathMethod.entrySet()) {
            temp1.add(methodName_method.getKey());
            String methodName = methodName_method.getValue().getMname();
            if(!Strings.isBlank(methodName) && !innerMatch.doNotRenameIndexes.contains(methodName_method.getKey())) {
                matchedMethods.put(methodName_method.getKey(), methodName);
                matchedSigMethods.put(methodName_method.getKey(), methodName_method.getValue());
            } // else several method name match, need more context
        }

        if(temp1.size() != 0) {
            if(f(unit, eClass, temp1)) {
                boolean res = fileMatches.addVersions(innerMatch.file, innerMatch.classPathMethod.values());
                if(!res) {
                    return false;
                }
                logger.i("Found match class: %s from file %s", innerMatch.className, innerMatch.file);
                addMatchedClass(eClass, innerMatch.className, true);
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
                for(Entry<Integer, MethodSignature> methodName_method: innerMatch.classPathMethod.entrySet()) {
                    MethodSignature strArray = methodName_method.getValue();
                    if(strArray.getPrototype().isEmpty()) {
                        continue; // shorty or several matched: can not reinject classes anyway
                    }
                    IDexMethod m = unit.getMethod(methodName_method.getKey());
                    IDexPrototype proto = unit.getPrototypes().get(m.getPrototypeIndex());
                    String prototypes = proto.generate(true);
                    if(prototypes.equals(strArray.getPrototype())) {
                        continue;
                    }
                    contextMatches.saveParamMatching(prototypes, strArray.getPrototype(),
                            innerMatch.className, strArray.getMname());
                }

                return true;
            }
            else {
                logger.debug("Can not validate candidate for %s: user threshold not reached", innerMatch.className);
                for(int e: temp1) {
                    matchedMethods.remove(e);
                    matchedSigMethods.remove(e);
                }
            }
        }
        return false;
    }

    @Override
    public boolean f(IDexUnit unit, IDexClass eClass, List<Integer> matchedMethods) {
        double totalInstrus = 0;
        double matchedInstrus = 0;

        List<? extends IDexMethod> methods = eClass.getMethods();
        Double c = instruCount.get(eClass.getIndex());
        if(c != null) {
            totalInstrus = c;
            for(int e: matchedMethods) {
                IDexMethod m = unit.getMethod(e);
                List<? extends IInstruction> insns = m.getInstructions();
                matchedInstrus += (insns == null ? 0: insns.size());
            }
        }
        else {
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
            }
            instruCount.put(eClass.getIndex(), totalInstrus);
        }

        if(methods.size() == 1 && !DexUtilLocal.isInnerClass(eClass.getSignature(true))) {
            // possible false positive: same constructor/super constructor only
            String name = methods.get(0).getName(true);
            if(name.equals("<init>") || name.equals("<clinit>")) {
                return matchedInstrus > 20; // artificial metrics
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
        Map<Integer, String> result = new HashMap<>();
        for(IAndrosigModule module: modules) {
            result.putAll(module.postProcessRenameMethods(unit, dexHashCodeList, firstRound));
        }
        return result;
    }

    private List<MethodSignature> getAlreadyMatched(IDexUnit dex, String className,
            List<? extends IDexMethod> methods, MatchingSearch search, String file) {
        List<MethodSignature> alreadyMatches = new ArrayList<>();
        for(IDexMethod eMethod: methods) {
            String methodName = matchedMethods.get(eMethod.getIndex());
            if(methodName == null) {
                continue;
            }
            MethodSignature ms = matchedSigMethods.get(eMethod.getIndex());
            if(ms == null) {
                // better to update matchedSigMethods (to retrieve callers on postProcessMethods)
                if(file != null) {
                    ms = search.findMethodMatch(file, className, eMethod, methodName);
                }
                if(ms != null) {
                    matchedSigMethods.put(eMethod.getIndex(), ms);
                }
                else {
                    IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
                    String prototypes = proto.generate(true);
                    String shorty = dex.getStrings().get(proto.getShortyIndex()).getValue();
                    ms = new MethodSignature(className, methodName, shorty, prototypes, null);
                }
            }
            alreadyMatches.add(ms);
        }
        return alreadyMatches;
    }

    @Override
    public Map<Integer, String> postProcessRenameClasses(IDexUnit dex, DexHashcodeList dexHashCodeList,
            boolean firstRound) {
        Map<Integer, String> result = new HashMap<>();
        for(IAndrosigModule module: modules) {
            result.putAll(module.postProcessRenameMethods(dex, dexHashCodeList, firstRound));
        }
        // maybe more parameter matches for method signatures (where only shorty matched previously)
        for(Entry<Integer, String> entry: matchedClasses.entrySet()) {
            IDexClass eClass = dex.getClass(entry.getKey());
            if(eClass == null) {
                // class not loaded in dex (maybe in another dex)
                continue;
            }
            DatabaseReferenceFile refFile = fileMatches.getFileFromClass(eClass);
            String f = null;
            if(refFile != null) {
                f = refFile.file;
            }
            if(f == null) {
                // update matchedClassesFile
                f = fileMatches.getMatchedClassFile(eClass, entry.getValue(), ref);
            }
            List<? extends IDexMethod> methods = eClass.getMethods();
            if(methods == null || methods.size() == 0) {
                // empty class
                continue;
            }
            String className = eClass.getSignature(true);

            MatchingSearch search = new MatchingSearch(dex, dexHashCodeList, ref, params, fileMatches, modules,
                    firstRound, false);
            List<MethodSignature> alreadyMatches = getAlreadyMatched(dex, className, methods, search, f);
            int matchedMethodsSize = alreadyMatches.size();
            do {
                List<String> files = null;
                matchedMethodsSize = alreadyMatches.size();
                for(IDexMethod eMethod: methods) {
                    if(!eMethod.isInternal() || matchedMethods.containsKey(eMethod.getIndex())) {
                        continue;
                    }
                    List<? extends IInstruction> instructions = eMethod.getInstructions();


                    if(files == null) {
                        // lazy file init of files
                        files = getCandidateFilesForClass(f, className);
                        if(files == null) {
                            // external library (not in signature files): no need to check other methods
                            break;
                        }
                    }

                    String methodNameMerged = "";
                    List<MethodSignature> strArrays = new ArrayList<>();
                    IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
                    String prototypes = proto.generate(true);
                    String shorty = dex.getStrings().get(proto.getShortyIndex()).getValue();
                    if(instructions != null) {
                        String mhash_tight = dexHashCodeList.getTightHashcode(eMethod);
                        if(mhash_tight == null) {
                            continue;
                        }
                        for(String file: files) {
                            MethodSignature strArray = search.findMethodMatch(file, mhash_tight, prototypes, shorty,
                                    className, alreadyMatches, eMethod, false);
                            if(strArray != null) {
                                String newMethodName = strArray.getMname();
                                if(newMethodName.isEmpty()) {
                                    methodNameMerged = null;
                                    break;
                                }
                                else if(methodNameMerged.isEmpty()) {
                                    methodNameMerged = newMethodName;
                                    strArrays.add(strArray);
                                }
                                else if(!methodNameMerged.equals(newMethodName)) {
                                    methodNameMerged = null;
                                    break;
                                }
                            }
                            else {
                                methodNameMerged = null;
                                break;
                            }
                        }
                    } // no instructions == no hash
                    if(Strings.isBlank(methodNameMerged) && !firstRound) {
                        // attempt signature matching only
                        methodNameMerged = "";
                        MethodSignature strArray = null;
                        for(String file: files) {
                            List<MethodSignature> sigs = search.getSignaturesForClassname(file, className, true,
                                    eMethod);
                            if(!sigs.isEmpty()) {
                                strArray = search.findMethodName(sigs, prototypes, shorty, className, alreadyMatches,
                                        eMethod);
                            }
                            if(strArray != null) {
                                String newMethodName = strArray.getMname();
                                if(newMethodName.isEmpty()) {
                                    methodNameMerged = null;
                                    break;
                                }
                                else if(methodNameMerged.isEmpty()) {
                                    methodNameMerged = newMethodName;
                                    strArrays.add(strArray);
                                }
                                else if(!methodNameMerged.equals(newMethodName)) {
                                    methodNameMerged = null;
                                    break;
                                }
                            }
                            else {
                                methodNameMerged = null;
                                break;
                            }
                        }
                    }

                    if(!Strings.isBlank(methodNameMerged)) {//&& !eMethod.getName(true).equals(methodName)) {
                        if(strArrays.size() == 1) {
                            MethodSignature strArray = strArrays.get(0);
                            matchedMethods.put(eMethod.getIndex(), methodNameMerged);
                            matchedSigMethods.put(eMethod.getIndex(), strArray);
                            alreadyMatches.add(strArray);

                            // postprocess: reinject class
                            if(!prototypes.equals(strArray.getPrototype())) {
                                contextMatches.saveParamMatching(prototypes, strArray.getPrototype(),
                                        className, methodNameMerged);
                            }
                        }
                        else {
                            contextMatches.saveMethodMatch(eMethod.getIndex(), methodNameMerged);
                        }
                    }
                }
            }
            while(matchedMethodsSize != alreadyMatches.size());

            // inject inheritance (sometimes only way for empty classes)
            if(f != null) {
                List<MethodSignature> allMethods = ref.getParentForClassname(f, className);
                if(allMethods != null && allMethods.size() == 1) {
                    List<String> supertypes = allMethods.get(0).getTargetSuperType();
                    List<String> interfaces = allMethods.get(0).getTargetInterfaces();
                    if(supertypes != null && !supertypes.isEmpty()) {
                        String supertype = supertypes.get(0);
                        contextMatches.saveClassMatchInherit(eClass.getSupertypes().get(0).getSignature(true),
                                supertype, className);
                    }
                    if(interfaces != null && !interfaces.isEmpty()) {
                        List<? extends ICodeType> realInterfaces = eClass.getImplementedInterfaces();
                        if(realInterfaces.size() == interfaces.size()) {
                            // remove same name
                            for(int i = 0; i < realInterfaces.size(); i++) {
                                String realSig = realInterfaces.get(i).getSignature(true);
                                for(int j = 0; j < interfaces.size(); j++) {
                                    String sig = interfaces.get(j);
                                    if(realSig.equals(sig)) {
                                        realInterfaces.remove(i);
                                        i--;
                                        interfaces.remove(j);
                                        break;
                                    }
                                }
                            }
                        }
                        if(realInterfaces.size() == 1) {
                            contextMatches.saveClassMatchInherit(realInterfaces.get(0).getSignature(true),
                                    interfaces.get(0), className);
                        }
                    }
                } // else TODO pick right version or parent data not available
            }
        }

        return result;
    }

    private List<String> getCandidateFilesForClass(String f, String className) {
        List<String> files = null;
        if(f == null) {
            files = ref.getFilesContainingClass(className);
            if(files == null) {
                // external library (not in signature files)
                return null;
            }
            if(files.size() > 1) {
                // attempt to retrieve only used resources/filter
                List<String> usedFiles = new ArrayList<>();
                for(String file: files) {
                    if(fileMatches.isSignatureFileUsed(file)) {
                        usedFiles.add(file);
                    }
                }
                if(!usedFiles.isEmpty()) {
                    files = usedFiles;
                }
            }
        }
        else {
            files = new ArrayList<>();
            files.add(f);
        }
        return files;
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
        for(Entry<String, ISignatureFile> sig: ref.getLoadedSignatureFiles().entrySet()) {
            if(fileMatches.isSignatureFileUsed(sig.getKey())) {
                sigCount += sig.getValue().getAllSignatureCount();
            }
        }
        return sigCount;
    }

    @Override
    public int getAllUsedSignatureFileCount() {
        return fileMatches.getSignatureFileUsed().size();
    }

    @Override
    public Map<String, LibraryInfo> getAllLibraryInfos() {
        Map<String, LibraryInfo> libs = new HashMap<>();
        for(Entry<Integer, String> entry: matchedClasses.entrySet()) {
            DatabaseReferenceFile file = fileMatches.getFileFromClassId(entry.getKey());
            if(file == null) {
                for(String used: fileMatches.getSignatureFileUsed()) {
                    LibraryInfo res = ref.getAllLibraryInfos(used).get(entry.getValue());
                    if(res != null) {
                        libs.put(entry.getValue(), res);
                        break;
                    }
                }
            }
            else {
                LibraryInfo res = ref.getAllLibraryInfos(file.file).get(entry.getValue());
                libs.put(entry.getValue(), res);
            }
        }
        return libs;
    }
}
