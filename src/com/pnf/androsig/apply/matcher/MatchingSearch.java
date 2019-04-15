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
import java.util.stream.Collectors;

import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.DexHashcodeList;
import com.pnf.androsig.apply.model.MethodSignature;
import com.pnf.androsig.apply.util.DexUtilLocal;
import com.pnfsoftware.jeb.core.units.code.IInstruction;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexPrototype;
import com.pnfsoftware.jeb.util.format.Strings;

/**
 * @author Cedric Lucas
 *
 */
class MatchingSearch {

    class InnerMatch {
        String className;
        Map<Integer, MethodSignature> classPathMethod = new HashMap<>();
        String file;
        Set<String> versions = new HashSet<>();
        List<Integer> doNotRenameIndexes = new ArrayList<>();

        public void validateVersions() {
            Map<String, Integer> versionOccurences = FileMatches.mergeVersions(null, classPathMethod.values());
            List<List<String>> preferedOrderList = fileMatches.orderVersions(versionOccurences);
            versions.addAll(preferedOrderList.get(0));
            // FIXME not only the preferred order: 2 preferred orders must be equally present
            List<Integer> illegalMethods = new ArrayList<>();
            for(Entry<Integer, MethodSignature> method: classPathMethod.entrySet()) {
                if(method.getValue().getVersions() == null) {
                    continue;
                }
                boolean found = false;
                for(String v: method.getValue().getVersions()) {
                    if(versions.contains(v)) {
                        found = true;
                        break;
                    }
                }
                if(!found) {
                    illegalMethods.add(method.getKey());
                }
            }
            for(Integer illegal: illegalMethods) {
                classPathMethod.remove(illegal);
            }
        }
    }

    private IDexUnit dex;
    private DexHashcodeList dexHashCodeList;
    private DatabaseReference ref;
    private DatabaseMatcherParameters params;
    private FileMatches fileMatches;
    private boolean firstRound;

    private Map<String, Map<String, InnerMatch>> fileCandidates = new HashMap<>(); // file -> (classname->count)

    public MatchingSearch(IDexUnit dex, DexHashcodeList dexHashCodeList, DatabaseReference ref,
            DatabaseMatcherParameters params, FileMatches fileMatches, boolean firstRound) {
        this.dex = dex;
        this.dexHashCodeList = dexHashCodeList;
        this.ref = ref;
        this.params = params;
        this.fileMatches = fileMatches;
        this.firstRound = firstRound;
    }

    public void processInnerClass(String file, Map<Integer, String> matchedMethods, List<? extends IDexMethod> methods,
            String innerClass, int innerLevel) {
        for(IDexMethod eMethod: methods) {
            if(!eMethod.isInternal() || matchedMethods.containsKey(eMethod.getIndex())) {
                continue;
            }
            String mhash_tight = dexHashCodeList.getTightHashcode(eMethod);
            if(mhash_tight == null) {
                continue;
            }
            List<MethodSignature> sigLine = ref.getSignatureLines(file, mhash_tight, true);
            if(sigLine == null) {
                continue;
            }
            sigLine = sigLine.stream().filter(s -> s.getCname().startsWith(innerClass)).collect(Collectors.toList());
            if(sigLine.isEmpty()) {
                continue;
            }
            Map<String, InnerMatch> classes = fileCandidates.get(file);
            if(classes == null) {
                classes = new HashMap<>();
                fileCandidates.put(file, classes);
            }
            saveTemporaryCandidate(dex, eMethod, sigLine, firstRound, classes, file, innerLevel);
        }
    }

    public void processClass(Map<Integer, String> matchedMethods, List<? extends IDexMethod> methods, int innerLevel) {
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
                    List<MethodSignature> sigLine = ref.getSignatureLines(file, mhash_tight, true);
                    Map<String, InnerMatch> classes = fileCandidates.get(file);
                    if(classes == null) {
                        classes = new HashMap<>();
                        fileCandidates.put(file, classes);
                    }
                    saveTemporaryCandidate(dex, eMethod, sigLine, firstRound, classes, file, innerLevel);
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
                        List<MethodSignature> sigLine = ref.getSignatureLines(file, mhash_loose, false);
                        Map<String, InnerMatch> classes = fileCandidates.get(file);
                        if(classes == null) {
                            classes = new HashMap<>();
                            fileCandidates.put(file, classes);
                        }
                        saveTemporaryCandidate(dex, eMethod, sigLine, firstRound, classes, file, innerLevel);
                    }
                }
            }
        }
    }

    private void saveTemporaryCandidate(IDexUnit dex, IDexMethod eMethod, List<MethodSignature> elts,
            boolean firstRound, Map<String, InnerMatch> classes, String file, int innerLevel) {
        IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
        String shorty = proto.getShorty();
        String prototype = proto.generate(true);

        // One class has several same sigs
        List<MethodSignature> realCandidates = elts.stream()
                .filter(strArray -> MethodSignature.getShorty(strArray).equals(shorty)
                        && MethodSignature.getPrototype(strArray).equals(prototype))
                .collect(Collectors.toList());
        if(!realCandidates.isEmpty()) {
            List<MethodSignature> strArrays = mergeSignaturesPerClass(realCandidates);
            for(MethodSignature strArray: strArrays) {
                String className = MethodSignature.getClassname(strArray);
                if(DexUtilLocal.getInnerClassLevel(className) != innerLevel) {
                    continue;
                }
                InnerMatch inner = classes.get(className);
                if(inner == null) {
                    inner = new InnerMatch();
                    inner.className = className;
                    inner.file = file;
                }
                inner.classPathMethod.put(eMethod.getIndex(), strArray);
                if(realCandidates.size() > 1) {
                    // we can not establish which method is the good one
                    // however, it is good to report that a matching was found (for percentage matching instructions
                    inner.doNotRenameIndexes.add(eMethod.getIndex());
                }
                classes.put(className, inner);
            }
        }
    }

    static MethodSignature mergeSignature(List<MethodSignature> results) {
        if(results == null || results.isEmpty()) {
            return null;
        }
        if(results.size() == 1) {
            return results.get(0);
        }
        String[] result = new String[9];
        for(int i = 0; i < 5; i++) {
            for(MethodSignature ress: results) {
                String[] res = ress.toTokens();
                if(i >= res.length) {
                    continue;
                }
                if(result[i] == null) {
                    result[i] = res[i];
                }
                else if(!result[i].equals(res[i])) {
                    result[i] = ""; // two lines differ here: may loose callers
                    if(i == 1) {
                        // String methodMatch = result[i] + " OR " + res[i];
                        // logger.debug("%s: There are several methods matching for signature %s: %s", ress.getCname(),
                        //         ress.getPrototype(), methodMatch);
                    }
                    break;
                }
            }
        }
        // merge versions
        Set<String> versions = new HashSet<>();
        for(MethodSignature value: results) {
            // put first as reference
            String[] vArray = MethodSignature.getVersions(value);
            if(vArray != null) {
                for(String version: vArray) {
                    versions.add(version);
                }
            }
        }
        return new MethodSignature(MethodSignature.getClassname(result), MethodSignature.getMethodName(result),
                MethodSignature.getShorty(result), MethodSignature.getPrototype(result), result[4],
                Strings.join(";", versions));
    }

    static List<MethodSignature> mergeSignaturesPerClass(List<MethodSignature> results) {
        if(results.size() < 2) {
            return results;
        }
        Map<String, List<MethodSignature>> sigs = new HashMap<>();
        for(MethodSignature result: results) {
            String className = result.getCname();
            List<MethodSignature> values = sigs.get(className);
            if(values == null) {
                values = new ArrayList<>();
                sigs.put(className, values);
            }
            values.add(result);
        }
        List<MethodSignature> merged = new ArrayList<>();
        for(List<MethodSignature> values: sigs.values()) {
            merged.add(mergeSignature(values));
        }
        return merged;
    }

    public boolean isEmpty() {
        return fileCandidates.isEmpty();
    }

    public Set<Entry<String, Map<String, InnerMatch>>> entrySet() {
        return fileCandidates.entrySet();
    }

}
