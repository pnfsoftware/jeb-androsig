/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.modules;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;

import com.pnf.androsig.apply.matcher.ContextMatches;
import com.pnf.androsig.apply.matcher.DatabaseMatcherParameters;
import com.pnf.androsig.apply.matcher.DatabaseReferenceFile;
import com.pnf.androsig.apply.matcher.FileMatches;
import com.pnf.androsig.apply.matcher.IAndrosigModule;
import com.pnf.androsig.apply.matcher.IDatabaseMatcher;
import com.pnf.androsig.apply.matcher.MatchingSearch;
import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.DexHashcodeList;
import com.pnf.androsig.apply.model.MethodSignature;
import com.pnf.androsig.apply.util.DexUtilLocal;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexPrototype;
import com.pnfsoftware.jeb.util.format.Strings;

/**
 * @author Cedric Lucas
 *
 */
public class ReverseMatchingModule implements IAndrosigModule {

    private IDatabaseMatcher dbMatcher;
    private ContextMatches contextMatches = new ContextMatches();
    private FileMatches fileMatches = new FileMatches();
    private DatabaseReference ref;

    private DatabaseMatcherParameters params;
    private List<IAndrosigModule> modules;

    public ReverseMatchingModule(IDatabaseMatcher dbMatcher, ContextMatches contextMatches, FileMatches fileMatches,
            DatabaseReference ref, DatabaseMatcherParameters params, List<IAndrosigModule> modules) {
        this.dbMatcher = dbMatcher;
        this.contextMatches = contextMatches;
        this.fileMatches = fileMatches;
        this.ref = ref;
        this.params = params;
        this.modules = modules;
    }

    @Override
    public void initNewPass(IDexUnit unit, DexHashcodeList dexHashCodeList, boolean firstRound) {
    }

    @Override
    public Map<Integer, String> postProcessRenameClasses(IDexUnit dex, DexHashcodeList dexHashCodeList,
            boolean firstRound) {
        if(!firstRound) {
            // search in used files if there are matching class that can apply to current project
            Map<DatabaseReferenceFile, List<ClassInfo>> mostUsed = getMostUsedFiles();
            MatchingSearch mSearch = new MatchingSearch(dex, dexHashCodeList, ref, params, fileMatches, modules,
                    firstRound, false);
            List<? extends IDexClass> classes = dex.getClasses();
            for(Entry<DatabaseReferenceFile, List<ClassInfo>> entry: mostUsed.entrySet()) {
                // is there a class in project that match?
                for(ClassInfo cl: entry.getValue()) {
                    Map<Integer, MethodSignature> bestCandidate = new HashMap<>();
                    IDexClass classCandidate = null;
                    List<MethodSignature> alreadyMatches = new ArrayList<>();
                    Map<Integer, MethodSignature> current = new HashMap<>();
                    long t0 = System.currentTimeMillis();
                    for(IDexClass eClass: classes) {
                        if(dbMatcher.getMatchedClasses().containsKey(eClass.getIndex())) {
                            continue;
                        }
                        // candidate?
                        List<? extends IDexMethod> methods = eClass.getMethods();
                        if(methods == null || methods.size() == 0
                                || methods.size() < params.reverseMatchingMethodThreshold
                                || methods.size() > cl.distinctSignaturesSize) {
                            // empty class or not enough methods or much methods regarding current class
                            continue;
                        }

                        for(IDexMethod m: methods) {
                            if(!m.isInternal()) {
                                continue;
                            }

                            MethodSignature sig = mSearch.findMethodName(cl.signatures, cl.classname, alreadyMatches,
                                    m);
                            if(sig != null && !Strings.isBlank(sig.getMname())) {
                                if(Strings.isBlank(sig.getPrototype())) {
                                    continue;
                                }
                                alreadyMatches.add(sig);
                                current.put(m.getIndex(), sig);
                            }
                        }

                        if(current.size() > bestCandidate.size()) {
                            bestCandidate = current;
                            classCandidate = eClass;
                        }
                    }
                    System.out.println("took " + (System.currentTimeMillis() - t0));

                    if(bestCandidate.size() < params.reverseMatchingMethodThreshold) {
                        continue;
                    }
                    // is best candidate a valid one?
                    int nbObjParam = 0;
                    for(Entry<Integer, MethodSignature> en: bestCandidate.entrySet()) {
                        String[] mparams = en.getValue().getPrototype().substring(1).split("\\)");
                        List<String> mparamsList = DexUtilLocal.parseSignatureParameters(mparams[0]);
                        mparamsList.add(mparams[1]); // return value

                        IDexPrototype proto = dex.getPrototypes().get(dex.getMethod(en.getKey()).getPrototypeIndex());
                        String prototypes = proto.generate(true);
                        String[] realParams = prototypes.substring(1).split("\\)");
                        List<String> realParamList = DexUtilLocal.parseSignatureParameters(realParams[0]);
                        realParamList.add(realParams[1]); // return value

                        for(int i = 0; i < mparamsList.size(); i++) {
                            String p = mparamsList.get(i);
                            String r = realParamList.get(i);
                            if(p.length() == 1) {
                                //native
                                continue;
                            }
                            else if(!p.equals("Ljava/lang/Object;") && !p.equals("Ljava/lang/String;") && p.equals(r)) {
                                nbObjParam++;
                            }
                        }
                    }
                    if(nbObjParam >= params.reverseMatchingComplexObjectThreshold) {
                        contextMatches.saveClassMatchInherit(classCandidate.getSignature(true), cl.classname, "");
                    }
                }
            }
        }
        return null;
    }

    @Override
    public Map<Integer, String> postProcessRenameMethods(IDexUnit unit, DexHashcodeList dexHashCodeList,
            boolean firstRound) {
        return null;
    }

    @Override
    public Set<MethodSignature> filterList(IDexUnit dex, IDexMethod eMethod, List<MethodSignature> results) {
        return null;
    }

    private int getDistinctSignaturesSize(List<MethodSignature> signatures) {
        Set<String> distinctSignature = new HashSet<>();
        for(MethodSignature m: signatures) {
            distinctSignature.add(m.getMname() + m.getPrototype());
        }
        return distinctSignature.size();
    }

    private class ClassInfo {
        public String classname;
        public List<MethodSignature> signatures;
        public int distinctSignaturesSize;

    }

    private ClassInfo buildClassInfo(DatabaseReferenceFile refFile, String classname) {
        if(dbMatcher.getMatchedClasses().containsValue(classname)) {
            return null;
        }
        List<MethodSignature> signatures = ref.getSignaturesForClassname(refFile, classname, true);
        int distinctSignaturesSize = 0;
        if(signatures.size() < params.reverseMatchingMethodThreshold
                || (distinctSignaturesSize = getDistinctSignaturesSize(
                        signatures)) < params.reverseMatchingMethodThreshold) {
            return null;
        }
        ClassInfo cl = new ClassInfo();
        cl.classname = classname;
        cl.signatures = signatures;
        cl.distinctSignaturesSize = distinctSignaturesSize;
        return cl;
    }

    private Map<DatabaseReferenceFile, List<ClassInfo>> getMostUsedFiles() {
        Map<DatabaseReferenceFile, Integer> fileOccurences = new HashMap<>();
        for(Entry<Integer, String> entry: dbMatcher.getMatchedClasses().entrySet()) {
            DatabaseReferenceFile refFile = fileMatches.getFileFromClassId(entry.getKey());
            if(refFile != null) {
                Integer occ = fileOccurences.get(refFile);
                occ = occ == null ? 1: occ + 1;
                fileOccurences.put(refFile, occ);
            }
        }
        Map<DatabaseReferenceFile, List<ClassInfo>> res = new HashMap<>();
        for(Entry<DatabaseReferenceFile, Integer> entry: fileOccurences.entrySet()) {
            if(entry.getValue() < params.reverseMatchingClassThreshold) {
                // too dangerous
                continue;
            }
            List<String> classes = ref.getClassList(entry.getKey().file);
            classes = classes.stream().filter(cl -> !DexUtilLocal.isInnerClass(cl)).collect(Collectors.toList());
            if(entry.getValue().doubleValue() / classes.size() >= params.reverseMatchingFoundClassPercentage) {
                // only track if 1/10 classes match
                List<ClassInfo> clInfoList = new ArrayList<>();
                res.put(entry.getKey(), clInfoList);
                for(String cl: classes) {
                    ClassInfo clInfo = buildClassInfo(entry.getKey(), cl);
                    if(clInfo != null) {
                        clInfoList.add(clInfo);
                    }
                }
            }
        }
        return res;
    }

}
