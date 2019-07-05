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
import com.pnf.androsig.apply.matcher.HierarchyMatcher;
import com.pnf.androsig.apply.matcher.IAndrosigModule;
import com.pnf.androsig.apply.matcher.MatchingSearch;
import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.DexHashcodeList;
import com.pnf.androsig.apply.model.MethodSignature;
import com.pnf.androsig.apply.util.DexUtilLocal;
import com.pnfsoftware.jeb.core.units.code.IInstruction;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexPrototype;
import com.pnfsoftware.jeb.util.base.Couple;
import com.pnfsoftware.jeb.util.format.Strings;

/**
 * @author Cedric Lucas
 *
 */
public class MethodFinderModule extends AbstractModule {

    private DatabaseMatcherParameters params;
    private List<IAndrosigModule> modules;

    public MethodFinderModule(ContextMatches contextMatches, FileMatches fileMatches,
            DatabaseReference ref, DatabaseMatcherParameters params, List<IAndrosigModule> modules) {
        super(contextMatches, fileMatches, ref);
        this.params = params;
        this.modules = modules;
    }

    @Override
    public void initNewPass(IDexUnit unit, DexHashcodeList dexHashCodeList, boolean firstRound) {
    }

    @Override
    public Map<Integer, String> postProcessRenameClasses(IDexUnit dex, DexHashcodeList dexHashCodeList,
            boolean firstRound) {
        // maybe more parameter matches for method signatures (where only shorty matched previously)
        for(Entry<Integer, String> entry: fileMatches.entrySetMatchedClasses()) {
            IDexClass eClass = dex.getClass(entry.getKey());
            if(eClass == null) {
                // class not loaded in dex (maybe in another dex)
                continue;
            }
            DatabaseReferenceFile refFile = fileMatches.getFileFromClass(dex, eClass);
            Set<DatabaseReferenceFile> refFiles = null;
            if(refFile == null) {
                // update matchedClassesFile
                refFile = fileMatches.getMatchedClassFile(dex, eClass, entry.getValue(), ref);
            }
            List<? extends IDexMethod> methods = eClass.getMethods();
            if(methods == null || methods.size() == 0) {
                // empty class
                continue;
            }
            String className = entry.getValue(); //eClass.getSignature(true); // watch out!! if class was not renamed (for example, anonymous classes)

            boolean safe = false;
            MatchingSearch search = new MatchingSearch(dex, dexHashCodeList, ref, params, fileMatches,
                    modules, firstRound, false, safe);
            List<MethodSignature> alreadyMatches = getAlreadyMatched(dex, className, methods, search, refFile);
            int matchedMethodsSize = alreadyMatches.size();
            do {
                matchedMethodsSize = alreadyMatches.size();
                for(IDexMethod eMethod: methods) {
                    if(!eMethod.isInternal() || fileMatches.containsMatchedMethod(eMethod)) {
                        continue;
                    }

                    if(refFiles == null) {
                        // lazy file init of files
                        if(refFile != null) {
                            refFiles = new HashSet<>();
                            refFiles.add(refFile);
                        }
                        else {
                            refFiles = fileMatches.getCandidateFilesFromClass(dex, eClass);
                        }
                        if(refFiles == null) {
                            break;
                        }
                    }

                    List<? extends IInstruction> instructions = eMethod.getInstructions();
                    String methodHint = getHintMethodName(eMethod);

                    String methodNameMerged = "";
                    List<MethodSignature> strArrays = new ArrayList<>();
                    IDexPrototype proto = dex.getPrototype(eMethod.getPrototypeIndex());
                    String prototypes = proto.generate(true);
                    String shorty = proto.getShorty();
                    if(methodHint == null && instructions != null && instructions.size() > params.methodSizeBar) {
                        String mhash_tight = dexHashCodeList.getTightHashcode(eMethod);
                        if(mhash_tight == null) {
                            continue;
                        }
                        for(DatabaseReferenceFile file: refFiles) {
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
                    if(methodHint != null || (Strings.isBlank(methodNameMerged) && !firstRound)) {
                        // attempt signature matching only
                        methodNameMerged = "";
                        Map<String, Map<DatabaseReferenceFile, MethodSignature>> strArraysMap = new HashMap<>();
                        List<DatabaseReferenceFile> toRemove = new ArrayList<>();
                        for(DatabaseReferenceFile file: refFiles) {
                            List<MethodSignature> sigs = search.getSignaturesForClassname(file, className, true,
                                    eMethod);
                            if(sigs.isEmpty()) {
                                continue;
                            }
                            if(methodHint != null) {
                                sigs = sigs.stream().filter(s -> methodHint.equals(s.getMname()))
                                        .collect(Collectors.toList());
                            }
                            MethodSignature strArray = search.findMethodName(sigs, prototypes, shorty, className,
                                    alreadyMatches, eMethod);
                            if(strArray != null) {
                                Map<DatabaseReferenceFile, MethodSignature> map = strArraysMap.get(strArray.getMname());
                                if(map == null) {
                                    map = new HashMap<>();
                                    strArraysMap.put(strArray.getMname(), map);
                                }
                                map.put(file, strArray);
                            }
                            else {
                                toRemove.add(file); // no method match in this file => not a good one
                            }
                        }
                        if(!toRemove.isEmpty() && toRemove.size() != refFiles.size()) {
                            // not a single reference found for signature
                            for(DatabaseReferenceFile r: toRemove) {
                                fileMatches.removeCandidateFile(r);
                            }
                        }
                        if(strArraysMap.size() == 1) {
                            Map<DatabaseReferenceFile, MethodSignature> map = strArraysMap.values().iterator().next();
                            strArrays = new ArrayList<>(map.values());
                            methodNameMerged = strArraysMap.keySet().iterator().next();
                        }
                    }

                    if(!Strings.isBlank(methodNameMerged)) {//&& !eMethod.getName(true).equals(methodName)) {
                        MethodSignature strArray = null;
                        if(strArrays.size() == 1) {
                            strArray = strArrays.get(0);
                        }
                        else {
                            strArray = MethodSignature.mergeSignatures(strArrays, false, eMethod);
                            if(strArray.getPrototype().isEmpty()) {
                                strArray = null;
                            }
                        }
                        if(strArray == null) {
                            // classes renamed or moved
                            saveMethodMatch(eMethod.getIndex(), methodNameMerged);
                        }
                        else {
                            fileMatches.addMatchedMethod(dex, eMethod.getIndex(), strArray);
                            alreadyMatches.add(strArray);
                        }
                    }
                }
                if(matchedMethodsSize == alreadyMatches.size() && !safe) {
                    safe = true;
                    search = new MatchingSearch(dex, dexHashCodeList, ref, params, fileMatches, modules,
                            firstRound, false, safe);
                    matchedMethodsSize++;
                }
            }
            while(matchedMethodsSize != alreadyMatches.size());

            // inject inheritance (sometimes only way for empty classes)
            if(refFile != null) {
                Couple<String, List<String>> hierarchy = ref.getParentForClassname(refFile, className);
                if(hierarchy != null) {
                    HierarchyMatcher hierarchyMgr = new HierarchyMatcher(eClass);
                    String supertype = hierarchy.getFirst();
                    List<String> interfaces = hierarchy.getSecond();
                    if(supertype != null) {
                        saveClassMatchInherit(hierarchyMgr.getSuperType(),
                                supertype, className);
                    }
                    if(interfaces != null && !interfaces.isEmpty()) {
                        List<String> realInterfaces = hierarchyMgr.getInterfaces();
                        // remove same name
                        for(int i = 0; i < realInterfaces.size(); i++) {
                            String realSig = realInterfaces.get(i);
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
                        if(realInterfaces.size() == 1 && interfaces.size() == 1) {
                            saveClassMatchInherit(realInterfaces.get(0), interfaces.get(0), className);
                        }
                        else if(!realInterfaces.isEmpty() && !interfaces.isEmpty()) {
                            // attempt to bind them
                            for(String interName: realInterfaces) {
                                // interfaces may not all be imported (obfuscation)
                                List<String> candidates = new ArrayList<>();
                                for(String c: interfaces) {
                                    if(DexUtilLocal.isCompatibleClasses(c, interName)) {
                                        candidates.add(c);
                                    }
                                }
                                if(candidates.size() == 1) {
                                    saveClassMatchInherit(interName, candidates.get(0), className);
                                    interfaces.remove(candidates.get(0));
                                }
                            }
                        }
                    }
                } // else wait for right version or parent data not available
            }
        }

        return new HashMap<>();
    }

    private String getHintMethodName(IDexMethod eMethod) {
        String methodHint = contextMatches.getMethod(eMethod.getIndex());
        if(methodHint == null) {
            return null;
        }
        return contextMatches.isValid(methodHint) ? methodHint: null;
    }

    @Override
    public Map<Integer, String> postProcessRenameMethods(IDexUnit unit, DexHashcodeList dexHashCodeList,
            boolean firstRound) {
        return new HashMap<>();
    }

    @Override
    public Set<MethodSignature> filterList(IDexUnit dex, IDexMethod eMethod, List<MethodSignature> results) {
        return null;
    }

    private List<MethodSignature> getAlreadyMatched(IDexUnit dex, String className, List<? extends IDexMethod> methods,
            MatchingSearch search, DatabaseReferenceFile file) {
        List<MethodSignature> alreadyMatches = new ArrayList<>();
        for(IDexMethod eMethod: methods) {
            String methodName = fileMatches.getMatchedMethod(eMethod);
            if(methodName == null) {
                continue;
            }
            MethodSignature ms = fileMatches.getMatchedSigMethod(eMethod);
            if(ms == null) {
                // better to update matchedSigMethods (to retrieve callers on postProcessMethods)
                if(file != null) {
                    ms = search.findMethodMatch(file, className, eMethod, methodName);
                }
                if(ms != null) {
                    fileMatches.bindMatchedSigMethod(dex, eMethod, ms);
                }
                else {
                    IDexPrototype proto = dex.getPrototype(eMethod.getPrototypeIndex());
                    String prototypes = proto.generate(true);
                    String shorty = proto.getShorty();
                    ms = new MethodSignature(className, methodName, shorty, prototypes, null);
                }
            }
            alreadyMatches.add(ms);
        }
        return alreadyMatches;
    }
}
