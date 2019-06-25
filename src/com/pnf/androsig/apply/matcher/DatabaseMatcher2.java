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
import com.pnf.androsig.apply.modules.MethodFinderModule;
import com.pnf.androsig.apply.modules.ReverseMatchingModule;
import com.pnf.androsig.apply.util.DexUtilLocal;
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

    /** user parameters */
    private DatabaseMatcherParameters params;

    private DatabaseReference ref;

    // class which should not be checked again
    private Set<Integer> ignoredClasses = new HashSet<>();
    // classes that seems to match but are not fully determined
    private Set<Integer> whiteListClasses = new HashSet<>();

    private ContextMatches contextMatches = new ContextMatches();

    private FileMatches fileMatches = new FileMatches(contextMatches);

    // **** Rebuild structure ****
    // Check duplicate classes (if two or more classes match to the same library class, we need to avoid rename these classes)
    private Map<String, ArrayList<Integer>> dupClasses = new HashMap<>();
    // Check duplicate methods (same as dupClass)
    private Map<Integer, ArrayList<Integer>> dupMethods = new HashMap<>();

    /** Cache of total instruction lines per class */
    private Map<Integer, Double> instruCount = new HashMap<>();

    /** Enabled modules */
    private List<IAndrosigModule> modules = new ArrayList<>();

    public DatabaseMatcher2(DatabaseMatcherParameters params, DatabaseReference ref) {
        this.params = params;
        this.ref = ref;
        // inner module, allow direct modification of matched methods
        modules.add(new MethodFinderModule(contextMatches, fileMatches, ref, params, modules));
        if(params.useCallerList) {
            modules.add(new ApkCallerModule(contextMatches, fileMatches, ref));
        }
        if(params.useReverseMatching) {
            modules.add(new ReverseMatchingModule(contextMatches, fileMatches, ref, params, modules));
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
                String newName = fileMatches.getMatchedClass(cl);
                if(newName == null) {
                    fileMatches.addMatchedClass(cl, entry.getValue());
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
            IDexMethod m = unit.getMethod(entry.getKey());
            String newName = fileMatches.getMatchedMethod(m);
            if(newName == null) {
                fileMatches.addMatchedMethod(m, entry.getValue());
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
                    fileMatches.removeMatchedClass(e);
                    // remove methods
                    for(Integer eMethod: dupMethods.get(e)) {
                        fileMatches.removeMatchedMethod(eMethod);
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
                    modules, true, true, false);
            int innerLevel = DexUtilLocal.getInnerClassLevel(originalSignature);
            fileCandidates.processClass(this, eClass, methods, innerLevel, files);

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
                fileMatches.addMatchedClass(eClass, innerMatch.getCname(), Arrays.asList(innerMatch.file),
                        innerMatch.getUsedMethodSignatures());
            }
            else {
                fileCandidates = new MatchingSearch(dex, dexHashCodeList, ref, params, fileMatches, modules,
                        false, true, false);
                innerLevel = DexUtilLocal.getInnerClassLevel(originalSignature);
                fileCandidates.processClass(this, eClass, methods, innerLevel, files);

                filterVersions(fileCandidates);
                candidates = new ArrayList<>();
            }
        }
    }

    private boolean storeFinalCandidates(IDexUnit unit, List<? extends IDexClass> classes,
            DexHashcodeList dexHashCodeList, boolean firstRound, boolean firstPass) {
        boolean found = false;
        for(IDexClass eClass: classes) {
            if(fileMatches.containsMatchedClass(eClass)) {
                continue;
            }
            // Get all candidates
            InnerMatch innerMatch = getClass(unit, eClass, dexHashCodeList, firstRound, firstPass);
            if(innerMatch != null) {
                if(storeFinalCandidate(unit, eClass, innerMatch, firstRound)) {
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
                modules, firstRound, unique, false);
        String originalSignature = eClass.getSignature(true);
        int innerLevel = DexUtilLocal.getInnerClassLevel(originalSignature);
        boolean parentClassFound = false;
        if(DexUtilLocal.isInnerClass(originalSignature)) {
            IDexClass parentClass = DexUtilLocal.getParentClass(dex, originalSignature);
            String name = parentClass == null ? null: fileMatches.getMatchedClass(parentClass);
            if(name != null) {
                parentClassFound = true;
                // parent class mapping found: what are the inner class defined for?
                DatabaseReferenceFile file = fileMatches.getFileFromClass(dex, parentClass);
                if(file != null) {
                    // Retrieve all inner class belonging to parent
                    String innerClass = name.substring(0, name.length() - 1) + "$";
                    List<MethodSignature> innerSignatures = ref.getSignaturesForClassname(file, innerClass, false);
                    HierarchyMatcher hierarchy = new HierarchyMatcher(eClass);

                    // is there only one class that can match?
                    Set<String> candidates = innerSignatures.stream().map(s -> s.getCname())
                            .collect(Collectors.toSet());
                    candidates = candidates.stream()
                            .filter(cname -> isInnerClassCandidate(dex, file, hierarchy, cname, eClass, innerLevel))
                            .collect(Collectors.toSet());
                    if(candidates.size() == 1) {
                        // bypass f validation
                        contextMatches.saveClassMatch(originalSignature, candidates.iterator().next(), name);
                        return null;
                    }

                    innerSignatures = innerSignatures.stream()
                            .filter(inner -> isInnerClassCandidate(dex, file, hierarchy, inner.getCname(), eClass,
                                    innerLevel))
                            .collect(Collectors.toList());
                    fileCandidates.processInnerClass(file, eClass, methods, innerClass, innerLevel,
                            innerSignatures);
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
        // First round: attempt to match a whole class
        // Look for candidate files: only uses hashcodes + prototype/compatible prototype
        boolean hasCandidates = true;
        if(fileCandidates.isEmpty()) {
            hasCandidates = fileCandidates.processClass(this, eClass, methods, innerLevel);
            if(!hasCandidates && !whiteListClasses.contains(eClass.getIndex())) {
                ignoredClasses.add(eClass.getIndex());
            }
        }

        if(fileCandidates.isEmpty()) {
            return null;
        }

        filterVersions(fileCandidates);

        if(unique) {
            // do not filter on second pass because interfaces can easily be modified (or new versions may be missed)
            filterHierarchy(fileCandidates, eClass);
        }

        findSmallMethods(fileCandidates, originalSignature, methods, unique);

        List<InnerMatch> bestCandidates = filterMaxMethodsMatch(fileCandidates);

        InnerMatch bestCandidate = null;
        if(bestCandidates.isEmpty()) {
            return null;
        }
        else if(bestCandidates.size() != 1) {
            // Find total number of methods per class and compare with methods.size()
            TreeMap<Integer, Set<InnerMatch>> diffMatch = new TreeMap<>();
            for(InnerMatch cand: bestCandidates) {
                Map<String, Integer> methodCountPerVersion = new HashMap<>();
                List<MethodSignature> allTight = ref.getSignaturesForClassname(cand.refFile, cand.getCname(), true);
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
        }

        if(bestCandidates.size() == 1) {
            bestCandidate = bestCandidates.get(0);
        }
        else {
            if(!firstRound) {
                String className = null;
                for(InnerMatch cand: bestCandidates) {
                    if(className == null) {
                        className = cand.getCname();
                    }
                    else if(!className.equals(cand.getCname())) {
                        className = null;
                        break;
                    }
                }
                if(className != null) {
                    // same classname (can happen with different versions of same lib)
                    DatabaseReferenceFile bestFile = fileMatches.getMatchedClassFile(dex, eClass, className, ref);
                    if(bestFile != null) {
                        for(InnerMatch cand: bestCandidates) {
                            if(cand.file.equals(bestFile.file)) {
                                bestCandidate = cand;
                                break;
                            }
                        }
                    }
                    else {
                        whiteListClasses.add(eClass.getIndex());
                        List<InnerMatch> newBestCandidates = new ArrayList<>();
                        for(InnerMatch cand: bestCandidates) {
                            if(f(dex, eClass, new ArrayList<>(cand.getMatchedMethodIndexes())) == null) {
                                newBestCandidates.add(cand);
                            }
                        }
                        if(newBestCandidates.size() == 1) {
                            bestCandidate = newBestCandidates.iterator().next();
                        }
                        else {
                            if(!unique) {
                                if(newBestCandidates.size() > 1) {
                                    contextMatches.saveClassMatchUnkownFile(originalSignature, className);
                                }
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
        if(bestCandidate.oneMatch) {
            if(DexUtilLocal.isInnerClass(originalSignature) && !parentClassFound) {
                return null;
            }
            // seriously check matching class: may be a false positive
            List<MethodSignature> allMethods = ref.getSignaturesForClassname(bestCandidate.refFile,
                    bestCandidate.getCname(), true);
            Set<String> methodNames = allMethods.stream().map(m -> m.getMname() + m.getPrototype())
                    .collect(Collectors.toSet());
            if(methodNames.size() != bestCandidate.methodsSize()) {
                // false positive most of the time: may investigate more here
                // expect to find match by param matching, safer
                return null;
            }
        }
        bestCandidate.validateMethods();
        return bestCandidate;
    }

    private void filterHierarchy(MatchingSearch fileCandidates, IDexClass eClass) {
        HierarchyMatcher hierarchy = new HierarchyMatcher(eClass);
        for(Entry<String, Map<String, InnerMatch>> entry: fileCandidates.entrySet()) {
            List<String> toRemove = new ArrayList<>();
            for(Entry<String, InnerMatch> cand: entry.getValue().entrySet()) {
                if(!hierarchy.isCompatible(ref, cand.getValue().refFile, cand.getValue().getCname())) {
                    toRemove.add(cand.getKey());
                }
            }
            for(String remove: toRemove) {
                entry.getValue().remove(remove);
            }
        }
    }

    private void filterVersions(MatchingSearch fileCandidates) {
        // here, we clean up the methods which don't belong to same version
        for(Entry<String, Map<String, InnerMatch>> entry: fileCandidates.entrySet()) {
            for(InnerMatch cand: entry.getValue().values()) {
                cand.validateVersions();
                if(cand.methodsSize() == 1) {
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
                    if(cand.containsMethod(eMethod.getIndex())) {
                        continue;
                    }
                    MethodSignature strArray = fileCandidates.findMethodMatch(cand.refFile, cand.getCname(),
                            cand.getUsedMethodSignatures(), eMethod, true);
                    if(strArray != null) {
                        cand.addMethod(eMethod.getIndex(), strArray);
                    }
                    else if(!firstPass && !cand.oneMatch) {
                        if(sigs == null) {
                            // lazy init
                            sigs = ref.getSignaturesForClassname(cand.refFile, cand.getCname(), true);
                        }
                        strArray = fileCandidates.findMethodName(sigs, cand.getCname(), new ArrayList<>(), eMethod);
                        if(strArray != null && strArray.getMname() != null && strArray.getPrototype() != null) {
                            cand.addMethod(eMethod.getIndex(), strArray);
                        }
                    }
                }
            }
        }
    }

    private boolean isInnerClassCandidate(IDexUnit dex, DatabaseReferenceFile file, HierarchyMatcher hierarchy,
            String classname, IDexClass eClass, int innerLevel) {
        IDexClass innerCl = dex.getClass(classname);
        // remove classes that already matched
        if(innerCl != null && fileMatches.containsMatchedClass(innerCl)) {
            return false;
        }
        if(DexUtilLocal.isAnonymous(eClass) != DexUtilLocal.isAnonymous(classname)) {
            return false;
        }
        if(innerLevel != DexUtilLocal.getInnerClassLevel(classname)) {
            return false;
        }
        if(!hierarchy.isCompatible(ref, file, classname)) {
            return false;
        }
        return true;
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
            if(candClass.methodsSize() > higherOccurence) {
                higherOccurence = candClass.methodsSize();
                bestCandidates.clear();
                bestCandidates.add(candClass);
            }
            else if(candClass.methodsSize() == higherOccurence) {
                bestCandidates.add(candClass);
            }
        }
        return higherOccurence;
    }



    /**
     * Validate a candidate match and save it.
     */
    protected boolean storeFinalCandidate(IDexUnit unit, IDexClass eClass, InnerMatch innerMatch, boolean firstRound) {
        if(fileMatches.containsMatchedClassValue(innerMatch.getCname())) {
            return false;
        }
        if(DexUtilLocal.isInnerClass(innerMatch.getCname())) {
            // allow renaming only when parent classes are fine, because inner class tend to be the same in some projects
            String originalSignature = eClass.getSignature(true);
            if(!DexUtilLocal.isInnerClass(originalSignature)) {
                // inner class match a non inner class => dangerous
                fileMatches.removeClassFiles(eClass);
                return false;
            }
            String parentSignature = originalSignature.substring(0, originalSignature.lastIndexOf("$")) + ";";
            String parentMatchSignature = innerMatch.getCname().substring(0, innerMatch.getCname().lastIndexOf("$"))
                    + ";";
            if(!parentSignature.equals(parentMatchSignature)) {
                // expect parent match: otherwise, wait for parent match
                if(firstRound) {
                    fileMatches.removeClassFiles(eClass);
                    return false;
                }
                else {
                    String oldClass = eClass.getSignature(true);
                    String newClass = innerMatch.getCname();
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
                        IDexClass newParentClassObj = unit.getClass(newParentClass);
                        String oldParentMatch = fileMatches.getMatchedClass(oldParentClassObj);
                        if(oldParentMatch != null) {
                            // parent class has already a match: must be the same
                            if(!oldParentMatch.equals(newParentClass)) {
                                fileMatches.removeClassFiles(eClass);
                                return false;
                            }
                        }
                        else if(newParentClassObj != null && fileMatches.containsMatchedClass(newParentClassObj)) {
                            // destination class is being/has been renamed but does not match the original class
                            fileMatches.removeClassFiles(eClass);
                            return false;
                        }
                    }
                    contextMatches.saveClassMatch(oldClass, newClass, innerMatch.getCname());
                }
            }
        }
        // Store methods
        ArrayList<Integer> temp1 = new ArrayList<>();
        if(innerMatch.methodsSize() == 0) {
            return false;
        }
        for(Entry<Integer, MethodSignature> methodName_method: innerMatch.entrySet()) {
            temp1.add(methodName_method.getKey());
            String methodName = methodName_method.getValue().getMname();
            if(!Strings.isBlank(methodName) && !innerMatch.doNotRenameIndexes.contains(methodName_method.getKey())) {
                fileMatches.addMatchedMethod(unit, methodName_method.getKey(), methodName_method.getValue());
            } // else several method name match, need more context
        }

        if(temp1.size() != 0) {
            String errorMessage = f(unit, eClass, temp1);
            if(errorMessage == null) {
                logger.debug("Found match class: %s from file %s", innerMatch.getCname(), innerMatch.file);
                fileMatches.addMatchedClass(eClass, innerMatch.getCname(), Arrays.asList(innerMatch.file),
                        innerMatch.getUsedMethodSignatures());
                ArrayList<Integer> tempArrayList = dupClasses.get(innerMatch.getCname());
                if(tempArrayList != null) {
                    tempArrayList.add(eClass.getIndex());
                    dupClasses.put(innerMatch.getCname(), tempArrayList);
                }
                else {
                    ArrayList<Integer> temp2 = new ArrayList<>();
                    temp2.add(eClass.getIndex());
                    dupClasses.put(innerMatch.getCname(), temp2);
                }
                dupMethods.put(eClass.getIndex(), temp1);

                // postprocess: reinject class
                for(Entry<Integer, MethodSignature> methodName_method: innerMatch.entrySet()) {
                    MethodSignature strArray = methodName_method.getValue();
                    if(strArray.getPrototype().isEmpty()
                            || innerMatch.doNotRenameIndexes.contains(methodName_method.getKey())) {
                        continue; // shorty or several matched: can not reinject classes anyway
                    }
                    IDexMethod m = unit.getMethod(methodName_method.getKey());
                    IDexPrototype proto = unit.getPrototypes().get(m.getPrototypeIndex());
                    String prototypes = proto.generate(true);
                    if(prototypes.equals(strArray.getPrototype())) {
                        continue;
                    }
                    contextMatches.saveParamMatching(prototypes, strArray.getPrototype(),
                            innerMatch.getCname(), strArray.getMname());
                }

                return true;
            }
            else {
                logger.info("Can not validate candidate for %s: %s", innerMatch.getCname(), errorMessage);
                for(int e: temp1) {
                    fileMatches.removeMatchedMethod(e);
                }
            }
        }
        return false;
    }

    @Override
    public String f(IDexUnit unit, IDexClass eClass, List<Integer> matchedMethods) {
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
                return "No method";
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
                return matchedInstrus > params.standaloneConstructorMethodSizeBar ? null
                        : "Only simple constructor match found";
            }
        }
        double cov = matchedInstrus / totalInstrus;
        if(cov <= params.matchedInstusPercentageBar) {
            return Strings.f("User threshold not reached: %.2f", cov);
        }
        return null;
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

    @Override
    public Map<Integer, String> postProcessRenameClasses(IDexUnit dex, DexHashcodeList dexHashCodeList,
            boolean firstRound) {
        Map<Integer, String> result = new HashMap<>();
        for(IAndrosigModule module: modules) {
            result.putAll(module.postProcessRenameClasses(dex, dexHashCodeList, firstRound));
        }
        return result;
    }

    /**
     * Get all matched classes.
     * 
     * @return a Map (key: index of a class. Value: a set of all matched classes(path))
     */
    @Override
    public Map<Integer, String> getMatchedClasses() {
        return fileMatches.getMatchedClasses();
    }

    /**
     * Get all matched methods.
     * 
     * @return a Map (Key: index of a method. Value: actual name of a method)
     */
    @Override
    public Map<Integer, String> getMatchedMethods() {
        return fileMatches.getMatchedMethods();
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
        for(Entry<Integer, String> entry: fileMatches.entrySetMatchedClasses()) {
            DatabaseReferenceFile file = fileMatches.getFileFromClassId(entry.getKey());
            if(file == null) {
                for(String used: fileMatches.getSignatureFileUsed()) {
                    LibraryInfo res = ref.getLibraryInfos(used, entry.getValue());
                    if(res != null) {
                        libs.put(entry.getValue(), res);
                        break;
                    }
                }
            }
            else {
                LibraryInfo res = ref.getLibraryInfos(file.file, null);
                if(file.getMergedVersions() != null && res.getVersions() == null) {
                    res.setVersions(file.getReducedVersions());
                }
                libs.put(entry.getValue(), res);
            }
        }
        return libs;
    }
}
