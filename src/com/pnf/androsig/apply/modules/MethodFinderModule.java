/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.modules;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

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
import com.pnfsoftware.jeb.core.units.code.ICodeType;
import com.pnfsoftware.jeb.core.units.code.IInstruction;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexPrototype;
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
                                saveParamMatching(prototypes, strArray.getPrototype(), className, methodNameMerged);
                            }
                        }
                        else {
                            saveMethodMatch(eMethod.getIndex(), methodNameMerged);
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
                        saveClassMatchInherit(eClass.getSupertypes().get(0).getSignature(true),
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
                            saveClassMatchInherit(realInterfaces.get(0).getSignature(true),
                                    interfaces.get(0), className);
                        }
                    }
                } // else TODO pick right version or parent data not available
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

    private List<MethodSignature> getAlreadyMatched(IDexUnit dex, String className, List<? extends IDexMethod> methods,
            MatchingSearch search, String file) {
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

}
