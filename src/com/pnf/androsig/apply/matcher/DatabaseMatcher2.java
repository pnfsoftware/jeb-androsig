/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import com.pnf.androsig.apply.matcher.ContextMatches.CMatch;
import com.pnf.androsig.apply.matcher.ContextMatches.Match;
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
    private Map<String, List<Integer>> dupClasses = new HashMap<>();
    // Check duplicate methods (same as dupClass)
    private Map<Integer, List<Integer>> dupMethods = new HashMap<>();

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

        applyContextMatch(unit, dexHashCodeList, firstRound, true);

        // remove duplicates
        for(Entry<String, List<Integer>> eClass: dupClasses.entrySet()) {
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

    private void applyContextMatch(IDexUnit unit, DexHashcodeList dexHashCodeList, boolean firstRound,
            boolean firstPass) {
        // expand: Add classes and methods found by context (method signature, caller)
        int size = 0;
        int oldSize = 0;
        do {
            oldSize = size;
            Set<String> matches = contextMatches.keySet();
            size = matches.size();
            Map<IDexClass, CMatch> bindings = new HashMap<>();
            Map<String, IDexClass> classesMatched = new HashMap<>();
            for(String oldName: matches) {
                CMatch cMatch = contextMatches.get(oldName);
                if(cMatch.processed) {
                    continue;
                }
                if(cMatch.name != null) {
                    removeWrongMethods(cMatch);
                    cMatch.processed = true;
                    continue;
                }
                IDexClass cl = unit.getClass(oldName);
                if(cl == null) {
                    continue;
                }
                String newName = fileMatches.getMatchedClass(cl);
                if(newName != null) {
                    continue;
                }
                String candidateNewName = null;
                List<Match> candidateNewNames = cMatch.matches;
                if(candidateNewNames.size() != 1) {
                    Match bestCandidate = null;
                    boolean eq = false;
                    for(Match cand: candidateNewNames) {
                        if(cand.newName.equals(cl.getSignature(true))) {
                            // quick win for samely named classes
                            bestCandidate = cand;
                            eq = false;
                            break;
                        }
                        if(bestCandidate == null) {
                            bestCandidate = cand;
                        }
                        else if(cand.count > bestCandidate.count) {
                            bestCandidate = cand;
                            eq = false;
                        }
                        else if(cand.count == bestCandidate.count) {
                            eq = true;
                        }
                    }
                    if(eq == true) {
                        // two candidates at same level, wait for more context matches
                        continue;
                    }
                    candidateNewName = bestCandidate.newName;
                }
                else {
                    candidateNewName = candidateNewNames.get(0).newName;
                }

                if(fileMatches.containsMatchedClassValue(candidateNewName)) {
                    // target class already exists! wait for more matching, since this one seems wrong
                    continue;
                }
                IDexClass cl2 = classesMatched.get(candidateNewName);
                if(cl2 == null) {
                    bindings.put(cl, cMatch);
                    classesMatched.put(candidateNewName, cl);
                    cMatch.name = candidateNewName;
                }
                else {
                    CMatch m = bindings.remove(cl2); // class name matches for 2 classes
                    if(m != null) {
                        // first duplicated discovered
                        m.processed = false;
                        m.name = null;
                    }
                }
            }
            for(Entry<IDexClass, CMatch> entry: bindings.entrySet()) {
                IDexClass cl = entry.getKey();
                CMatch cMatch = entry.getValue();
                InnerMatch innerMatch = getClass(unit, cl, dexHashCodeList, firstRound, false, cMatch.name);
                if(innerMatch != null) {
                    storeFinalCandidate(unit, cl, innerMatch, firstRound, false);
                    cMatch.processed = true;
                }
                else if(!firstRound) {
                    // Shoud only happen when detecting classes not in libs
                    fileMatches.addMatchedClass(cl, cMatch.name, null, null);
                    cMatch.processed = true;
                }
                if(cMatch.processed && cMatch.matches.size() > 1) {
                    removeWrongMethods(cMatch);
                }
                if(!cMatch.processed) {
                    cMatch.name = null;
                }
            }
        }
        while(oldSize != size);
        for(Entry<Integer, String> entry: contextMatches.methodsEntrySet()) {
            if(!contextMatches.isValid(entry.getValue())) {
                continue;
            }
            IDexMethod m = unit.getMethod(entry.getKey());
            String newName = fileMatches.getMatchedMethod(m);
            if(newName != null && !newName.equals(entry.getValue())) {
                logger.warn("Conflict for method: Method %s was already renamed to %s. Can not rename to %s",
                        m.getName(false), newName, entry.getValue());
                contextMatches.setInvalidMethod(entry.getKey());
            }
        }
    }

    private void removeWrongMethods(CMatch cMatch) {
        // remove wrong methods
        for(Match match: cMatch.matches) {
            if(match.newName.equals(cMatch.name)) {
                continue;
            }
            for(Integer wrongMethod: match.methodIndexes) {
                fileMatches.removeMatchedMethod(wrongMethod);
                // TODO perform unrenaming
            }
        }
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
                fileMatches.addMatchedClass(eClass, innerMatch.getCname(), innerMatch.getFiles(),
                        innerMatch.getUsedMethodSignatures());
            }
            else {
                fileCandidates = new MatchingSearch(dex, dexHashCodeList, ref, params, fileMatches, modules,
                        false, true);
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
            InnerMatch innerMatch = getClass(unit, eClass, dexHashCodeList, firstRound, firstPass, null);
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
            boolean unique, String hintName) {
        List<? extends IDexMethod> methods = eClass.getMethods();
        if(hintName == null && (methods == null || methods.size() == 0)) {
            // since signature only contains non empty classes, there is no chance that we found by matching
            return null;
        }

        MatchingSearch matching = new MatchingSearch(dex, dexHashCodeList, ref, params, fileMatches,
                modules, firstRound, unique);
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
                    String innerClass = hintName == null ? (name.substring(0, name.length() - 1) + "$"): hintName;
                    List<MethodSignature> innerSignatures = ref.getSignaturesForClassname(file, innerClass, false);
                    HierarchyMatcher hierarchy = new HierarchyMatcher(eClass);

                    // is there only one class that can match?
                    Set<String> candidates = innerSignatures.stream().map(s -> s.getCname())
                            .collect(Collectors.toSet());
                    candidates = candidates.stream()
                            .filter(cname -> isInnerClassCandidate(dex, file, hierarchy, cname, eClass, innerLevel))
                            .collect(Collectors.toSet());
                    if(hintName == null && candidates.size() == 1) {
                        // bypass f validation
                        contextMatches.saveClassMatch(originalSignature, candidates.iterator().next(), name);
                        return null;
                    }

                    innerSignatures = innerSignatures.stream()
                            .filter(inner -> isInnerClassCandidate(dex, file, hierarchy, inner.getCname(), eClass,
                                    innerLevel))
                            .collect(Collectors.toList());
                    matching.processInnerClass(file, eClass, methods, innerClass, innerLevel,
                            innerSignatures);
                    ignoredClasses.remove(eClass.getIndex());

                    if(matching.isEmpty() && hintName != null) {
                        // no matching/no methods?
                        return new InnerMatch(hintName, file.file);
                    }
                }
                else {
                    //System.out.println("No reference file for " + parentSignature);
                }
            }
            else {
                // Inner class, in general are more or less like a method (in terms of data match), so wait for parent to be matched before analysis
                if(hintName != null) {
                    // search as a normal class
                }
                else if(firstRound || unique) {
                    return null;
                }
            }
        }

        if(hintName == null && ignoredClasses.contains(eClass.getIndex())) {
            return null;
        }
        // First round: attempt to match a whole class
        // Look for candidate files: only uses hashcodes + prototype/compatible prototype
        boolean hasCandidates = true;
        if(matching.isEmpty()) {
            hasCandidates = matching.processClass(this, eClass, methods, innerLevel);
            if(!hasCandidates && !whiteListClasses.contains(eClass.getIndex())) {
                // there may be alternative, multi matching, by finding context
                //ignoredClasses.add(eClass.getIndex());
            }
        }

        if (hintName != null) {
            matching.filterClassName(hintName);
        }

        if(matching.isEmpty()) {
            return null;
        }

        filterVersions(matching);

        if(unique) {
            // do not filter on second pass because interfaces can easily be modified (or new versions may be missed)
            filterHierarchy(matching, eClass);
        }

        findSmallMethods(matching, originalSignature, methods, unique);

        List<InnerMatch> bestCandidates = filterMaxMethodsMatch(dex, matching);

        InnerMatch bestCandidate = null;
        if(bestCandidates.isEmpty()) {
            return null;
        }
        else if(bestCandidates.size() != 1) {
            // Find total number of methods per class and compare with methods.size()
            TreeMap<Integer, Set<InnerMatch>> diffMatch = new TreeMap<>();
            for(InnerMatch cand: bestCandidates) {
                Map<String, Integer> methodCountPerVersion = new HashMap<>();
                List<MethodSignature> allTight = ref.getSignaturesForClassname(cand.getFirstRefFile(), cand.getCname(),
                        true);
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
            if(!diffMatch.isEmpty()) {
                bestCandidates = new ArrayList<>(diffMatch.get(diffMatch.firstKey()));
            }
        }

        if(bestCandidates.size() == 1) {
            bestCandidate = bestCandidates.get(0);
        }
        else {
            if(!firstRound) {
                String className = getUniqueName(bestCandidates);
                if(className != null) {
                    // same classname (can happen with different versions of same lib)
                    DatabaseReferenceFile bestFile = fileMatches.getMatchedClassFile(dex, eClass, className, ref);
                    if(bestFile != null) {
                        // Watch out: bestFile may rarely NOT be the valid file (for example if class was moved to a newer artifact)
                        bestLoop: for(InnerMatch cand: bestCandidates) {
                            for(String f: cand.getFiles()) {
                                if(f.equals(bestFile.file)) {
                                    bestCandidate = cand;
                                    break bestLoop;
                                }
                            }
                        }
                    }
                    if(bestCandidate == null) {
                        whiteListClasses.add(eClass.getIndex());
                        List<InnerMatch> newBestCandidates = new ArrayList<>();
                        for(InnerMatch cand: bestCandidates) {
                            if(hintName != null
                                    || f(dex, eClass, new ArrayList<>(cand.getMatchedMethodIndexes())) == null) {
                                newBestCandidates.add(cand);
                            }
                        }
                        if(newBestCandidates.size() == 1) {
                            bestCandidate = newBestCandidates.iterator().next();
                        }
                        else {
                            if(hintName != null || !newBestCandidates.isEmpty()) {
                                if(!unique) {
                                    bestCandidate = InnerMatch.mergeCandidates(dex, newBestCandidates, true);
                                }
                                else {
                                    boolean valid = false;
                                    for(InnerMatch cand: newBestCandidates) {
                                        if(validateOneMatch(matching, dex, cand, originalSignature, parentClassFound)) {
                                            valid = true;
                                            break;
                                        }
                                    }
                                    if(valid && hintName == null) {
                                        // file not determined, save the hint
                                        contextMatches.saveClassMatchUnkownFile(originalSignature, className);
                                    }
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
        if(hintName == null && !validateOneMatch(matching, dex, bestCandidate, originalSignature, parentClassFound)) {
            return null;
        }
        bestCandidate.validateMethods();
        return bestCandidate;
    }

    private boolean validateOneMatch(MatchingSearch matching, IDexUnit dex, InnerMatch bestCandidate, String originalSignature,
            boolean parentClassFound) {
        if(bestCandidate.oneMatch) {
            if(DexUtilLocal.isInnerClass(originalSignature)) {
                return parentClassFound;
            }
            // seriously check matching class: may be a false positive
            if(bestCandidate.methodsSize() > params.matchedMethodsOneMatch) {
                return true;
            }
            // valid if at least 2 true matches
            int complexSignatureFound = 0;
            for(Entry<Integer, MethodSignature> entry: bestCandidate.entrySet()) {
                if(entry.getValue().getPrototype().isEmpty()) {
                    continue;
                }
                if(matching.isComplexSignature(entry.getValue().getPrototype())) {
                    // complex signatures found
                    complexSignatureFound++;
                }
                else {
                    // same name (except generic names)
                    String methodName = dex.getMethod(entry.getKey()).getName(true);
                    if(!entry.getValue().getMname().equals(methodName)) {
                        continue;
                    }
                    if(DexUtilLocal.isObjectInheritedMethod(entry.getValue().getMname(),
                            entry.getValue().getPrototype())) {
                        continue;
                    }
                    complexSignatureFound++;
                }
            }
            return complexSignatureFound > 1;
        }
        return true;
    }

    private void filterHierarchy(MatchingSearch fileCandidates, IDexClass eClass) {
        HierarchyMatcher hierarchy = new HierarchyMatcher(eClass);
        for(Entry<String, Map<String, InnerMatch>> entry: fileCandidates.entrySet()) {
            List<String> toRemove = new ArrayList<>();
            for(Entry<String, InnerMatch> cand: entry.getValue().entrySet()) {
                if(!hierarchy.isCompatible(ref, cand.getValue().getFirstRefFile(), cand.getValue().getCname())) {
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
                    boolean signatureUsed = false;
                    for(String f: cand.getFiles()) {
                        if(fileMatches.isSignatureFileUsed(f)) {
                            signatureUsed = true;
                            break;
                        }
                    }
                    if(!signatureUsed) {
                        continue;
                    }
                }
                List<MethodSignature> sigs = null;
                for(IDexMethod eMethod: methods) {
                    if(cand.containsMethod(eMethod.getIndex())) {
                        continue;
                    }
                    MethodSignature strArray = fileCandidates.findMethodMatch(cand.getFirstRefFile(), cand.getCname(),
                            cand.getUsedMethodSignatures(), eMethod, true);
                    if(strArray != null) {
                        cand.addMethod(eMethod, strArray);
                    }
                    else if(!firstPass && !cand.oneMatch) {
                        if(sigs == null) {
                            // lazy init
                            sigs = ref.getSignaturesForClassname(cand.getFirstRefFile(), cand.getCname(), true);
                        }
                        strArray = fileCandidates.findMethodName(sigs, cand.getCname(), new ArrayList<>(), eMethod);
                        if(strArray != null && strArray.getMname() != null && strArray.getPrototype() != null) {
                            cand.addMethod(eMethod, strArray);
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

    private Boolean internalUse = null;

    private List<InnerMatch> filterMaxMethodsMatch(IDexUnit dex, MatchingSearch fileCandidates) {
        // First retrieve best candidates with 2 splits (internal vs non internal)
        Integer higherOccurence = 0;
        List<InnerMatch> bestCandidates = new ArrayList<>();
        Integer higherOccurenceInternal = 0;
        List<InnerMatch> bestCandidatesInternal = new ArrayList<>();
        Map<String, List<InnerMatch>> candidatesPerName = new HashMap<>();
        for(Entry<String, Map<String, InnerMatch>> cand: fileCandidates.entrySet()) {
            for(Entry<String, InnerMatch> entry: cand.getValue().entrySet()) {
                String classname = entry.getKey();
                InnerMatch candClass = entry.getValue();
                List<InnerMatch> value = candidatesPerName.get(classname);
                if(value == null) {
                    value = new ArrayList<>();
                    candidatesPerName.put(classname, value);
                }
                value.add(candClass);

                if(classname.startsWith("Landroid/support/") && classname.contains("/internal/")) {
                    if(candClass.methodsSize() > higherOccurenceInternal) {
                        higherOccurenceInternal = candClass.methodsSize();
                        bestCandidatesInternal.clear();
                        bestCandidatesInternal.add(candClass);
                    }
                    else if(candClass.methodsSize() == higherOccurenceInternal) {
                        bestCandidatesInternal.add(candClass);
                    }
                }
                else if(candClass.methodsSize() > higherOccurence) {
                    higherOccurence = candClass.methodsSize();
                    bestCandidates.clear();
                    bestCandidates.add(candClass);
                }
                else if(candClass.methodsSize() == higherOccurence) {
                    bestCandidates.add(candClass);
                }
            }
        }

        // Second, decide if use internal or not (look for alternatives)
        if(!bestCandidatesInternal.isEmpty()) {
            String shortName = getUniqueName(bestCandidates);
            String internalName = getUniqueName(bestCandidatesInternal);
            if(shortName != null && internalName != null && shortName.equals(internalName.replace("/internal/", "/"))) {
                // same classes;
                if(internalUse == null) {
                    internalUse = higherOccurenceInternal > higherOccurence;
                }
                if(internalUse) {
                    candidatesPerName.get(internalName).addAll(candidatesPerName.get(shortName));
                    bestCandidates = bestCandidatesInternal;
                }
                else {
                    candidatesPerName.get(shortName).addAll(candidatesPerName.get(internalName));
                }
            }
            else {
                if(higherOccurenceInternal > higherOccurence) {
                    bestCandidates = bestCandidatesInternal;
                }
            }
        }

        // Quick-win on one result class
        if(bestCandidates.size() == 1) {
            // merge other methods?
            InnerMatch first = bestCandidates.get(0);

            List<InnerMatch> altCandidates = candidatesPerName.get(first.getCname());
            if(altCandidates.size() <= 1) {
                return bestCandidates;
            }
            altCandidates.remove(first);
            altCandidates.add(0, first);// set main candidate at beginning
            InnerMatch newCand = InnerMatch.mergeCandidates(dex, altCandidates, false);
            bestCandidates.clear();
            bestCandidates.add(newCand);
            return bestCandidates; // still keep precedence for first file
        }

        //String name = getUniqueName(bestCandidates);
        //if(name != null) {
        // merge later for now
        //}
        return bestCandidates;
    }

    private static String getUniqueName(List<InnerMatch> bestCandidates) {
        String className = null;
        if(!bestCandidates.isEmpty()) {
            for(InnerMatch cand: bestCandidates) {
                if(className == null) {
                    className = cand.getCname();
                }
                else if(!className.equals(cand.getCname())) {
                    className = null;
                    break;
            }
        }
        }
        return className;
    }

    protected boolean storeFinalCandidate(IDexUnit unit, IDexClass eClass, InnerMatch innerMatch, boolean firstRound) {
        return storeFinalCandidate(unit, eClass, innerMatch, firstRound, true);
    }

    /**
     * Validate a candidate match and save it.
     */
    private boolean storeFinalCandidate(IDexUnit unit, IDexClass eClass, InnerMatch innerMatch, boolean firstRound,
            boolean checkCoverage) {
        if(fileMatches.containsMatchedClassValue(innerMatch.getCname())) {
            return false;
        }
        String originalSignature = eClass.getSignature(true);
        if(DexUtilLocal.getInnerClassLevel(innerMatch.getCname()) != DexUtilLocal
                .getInnerClassLevel(originalSignature)) {
            return false;
        }
        if(DexUtilLocal.isInnerClass(innerMatch.getCname())) {
            // allow renaming only when parent classes are fine, because inner class tend to be the same in some projects
            String oldClass = originalSignature;
            String newClass = innerMatch.getCname();
            if(!DexUtilLocal.isInnerClass(oldClass)) {
                // inner class match a non inner class => dangerous
                return false;
            }
            String parentSignature = DexUtilLocal.getParentSignature(oldClass);
            String parentMatchSignature = DexUtilLocal.getParentSignature(newClass);
            if(!parentSignature.equals(parentMatchSignature)) {
                // expect parent match: otherwise, wait for parent match
                if(firstRound) {
                    return false;
                }
                else {
                    // Preprocess: if new class is already renamed, there is no reason to move another one
                    String oldParentClass = oldClass;
                    String newParentClass = newClass;
                    while(DexUtilLocal.isInnerClass(newParentClass)) {
                        oldParentClass = DexUtilLocal.getParentSignature(oldParentClass);
                        newParentClass = DexUtilLocal.getParentSignature(newParentClass);
                        IDexClass oldParentClassObj = unit.getClass(oldParentClass);
                        if(oldParentClassObj == null) {
                            continue;
                        }
                        IDexClass newParentClassObj = unit.getClass(newParentClass);
                        String oldParentMatch = fileMatches.getMatchedClass(oldParentClassObj);
                        if(oldParentMatch != null) {
                            // parent class has already a match: must be the same
                            if(!oldParentMatch.equals(newParentClass)) {
                                return false;
                            }
                        }
                        else if(newParentClassObj != null && fileMatches.containsMatchedClass(newParentClassObj)) {
                            // destination class is being/has been renamed but does not match the original class
                            return false;
                        }
                    }
                }
            }
        }
        // Store methods
        if(checkCoverage && innerMatch.methodsSize() == 0) {
            return false;
        }
        List<Integer> temp1 = new ArrayList<>(innerMatch.getMatchedMethodIndexes());
        if(!checkCoverage || temp1.size() != 0) {
            String errorMessage = checkCoverage ? f(unit, eClass, temp1): null;
            if(errorMessage == null) {
                logger.debug("Found match class: %s from file %s", innerMatch.getCname(),
                        Strings.join(",", innerMatch.getFiles()));
                fileMatches.addMatchedClass(eClass, innerMatch.getCname(), innerMatch.getFiles(),
                        innerMatch.getUsedMethodSignatures());
                if(DexUtilLocal.isInnerClass(innerMatch.getCname())) {
                    // Add parent as context matches
                    contextMatches.saveClassMatch(originalSignature, innerMatch.getCname(), innerMatch.getCname());
                }
                List<Integer> tempArrayList = dupClasses.get(innerMatch.getCname());
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

                // bind methods
                for(Entry<Integer, MethodSignature> methodName_method: innerMatch.entrySet()) {
                    Integer mIndex = methodName_method.getKey();
                    MethodSignature strArray = methodName_method.getValue();
                    String methodName = strArray.getMname();
                    if(Strings.isBlank(methodName) || innerMatch.doNotRenameIndexes.contains(mIndex)) {
                        // several method name match, need more context
                        continue;
                    }
                    fileMatches.addMatchedMethod(unit, mIndex, strArray);
                }

                return true;
            }
            else {
                logger.info("Can not validate candidate %s for %s: %s", innerMatch.getCname(), originalSignature,
                        errorMessage);
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
