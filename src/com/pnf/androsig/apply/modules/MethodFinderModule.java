/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.modules;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import com.pnf.androsig.apply.matcher.ContextMatches;
import com.pnf.androsig.apply.matcher.DatabaseMatcherParameters;
import com.pnf.androsig.apply.matcher.DatabaseReferenceFile;
import com.pnf.androsig.apply.matcher.FileMatches;
import com.pnf.androsig.apply.matcher.HierarchyMatcher;
import com.pnf.androsig.apply.matcher.IAndrosigModule;
import com.pnf.androsig.apply.matcher.IDatabaseMatcher;
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

    private Map<Integer, String> matchedMethods;
    private Map<Integer, MethodSignature> matchedSigMethods;

    private DatabaseMatcherParameters params;
    private List<IAndrosigModule> modules;

    public MethodFinderModule(IDatabaseMatcher dbMatcher, ContextMatches contextMatches, FileMatches fileMatches,
            DatabaseReference ref, DatabaseMatcherParameters params, List<IAndrosigModule> modules,
            Map<Integer, String> matchedMethods, Map<Integer, MethodSignature> matchedSigMethods) {
        super(dbMatcher, contextMatches, fileMatches, ref);
        this.matchedMethods = matchedMethods;
        this.matchedSigMethods = matchedSigMethods;
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
        Map<Integer, String> matchedClasses = getMatchedClasses();
        for(Entry<Integer, String> entry: matchedClasses.entrySet()) {
            IDexClass eClass = dex.getClass(entry.getKey());
            if(eClass == null) {
                // class not loaded in dex (maybe in another dex)
                continue;
            }
            DatabaseReferenceFile refFile = fileMatches.getFileFromClass(dex, eClass);
            if(refFile == null) {
                // update matchedClassesFile
                refFile = fileMatches.getMatchedClassFile(dex, eClass, entry.getValue(), ref);
            }
            List<? extends IDexMethod> methods = eClass.getMethods();
            if(methods == null || methods.size() == 0) {
                // empty class
                continue;
            }
            String className = eClass.getSignature(true);

            boolean safe = false;
            MatchingSearch search = new MatchingSearch(getDbMatcher(), dex, dexHashCodeList, ref, params, fileMatches,
                    modules, firstRound, false, safe);
            List<MethodSignature> alreadyMatches = getAlreadyMatched(dex, className, methods, search, refFile);
            int matchedMethodsSize = alreadyMatches.size();
            do {
                List<DatabaseReferenceFile> files = null;
                matchedMethodsSize = alreadyMatches.size();
                for(IDexMethod eMethod: methods) {
                    if(!eMethod.isInternal() || matchedMethods.containsKey(eMethod.getIndex())) {
                        continue;
                    }
                    List<? extends IInstruction> instructions = eMethod.getInstructions();

                    if(files == null) {
                        // lazy file init of files
                        List<String> rawFiles = getCandidateFilesForClass(refFile, className);
                        if(rawFiles == null) {
                            // external library (not in signature files): no need to check other methods
                            break;
                        }
                        files = new ArrayList<>();
                        for(String rf: rawFiles) {
                            DatabaseReferenceFile f = fileMatches.getFromFilename(rf);
                            if(f == null) {
                                f = new DatabaseReferenceFile(rf, null);
                            }
                            files.add(f);
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
                        for(DatabaseReferenceFile file: files) {
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
                        for(DatabaseReferenceFile file: files) {
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
                                saveParamMatching(prototypes, strArray.getPrototype(), className, methodNameMerged);
                            }
                        }
                        else {
                            saveMethodMatch(eMethod.getIndex(), methodNameMerged);
                        }
                    }
                }
                if(matchedMethodsSize == alreadyMatches.size() && !safe) {
                    safe = true;
                    search = new MatchingSearch(getDbMatcher(), dex, dexHashCodeList, ref, params, fileMatches, modules,
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
                } // else TODO pick right version or parent data not available
            }
        }

        return new HashMap<>();
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

    private List<String> getCandidateFilesForClass(DatabaseReferenceFile f, String className) {
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
            files.add(f.file);
        }
        return files;
    }

}
