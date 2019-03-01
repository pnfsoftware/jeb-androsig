/*
 * JEB Copyright PNF Software, Inc.
 * 
 *     https://www.pnfsoftware.com
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.pnf.androsig.apply.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;

import com.pnf.androsig.apply.util.MetadataGroupHandler;
import com.pnf.androsig.apply.util.StructureHandler;
import com.pnf.androsig.common.SignatureHandler;
import com.pnfsoftware.jeb.core.output.ItemClassIdentifiers;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexPrototype;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * The class contains all information about the project structure.
 * 
 * @author Ruoxiao Wang
 *
 */
public class StructureInfo {
    private final ILogger logger = GlobalLog.getLogger(StructureInfo.class);

    // method map (method.getSignature(false), method.getSignature(true))
    // used by DexMetadataGroup
    private Map<String, String> matchedMethods_new_orgPath;
    private Map<String, String> matchedClasses_new_orgPath;

    // Modified classes
    private Set<Integer> modifiedClasses;


    private DatabaseMatcher dbMatcher;

    // TODO remove
    private DexHashcodeList methodHashcodes;
    private Map<String, List<String[]>> allTightSignatures;
    private Map<String, List<String[]>> allLooseSignatures;

    public StructureInfo() {
        matchedMethods_new_orgPath = new HashMap<>();
        matchedClasses_new_orgPath = new HashMap<>();

        modifiedClasses = new HashSet<>();

        dbMatcher = new DatabaseMatcher();
    }

    /**
     * Get method original signature through new signature
     * 
     * @return a Map (Key: method new signature. Value: method original signature)
     */
    public Map<String, String> getMatchedMethods_new_orgPath() {
        return matchedMethods_new_orgPath;
    }

    /**
     * Get class original signature through new signature
     * 
     * @return a Map (Key: class new signature. Value: class original signature)
     */
    public Map<String, String> getMatchedClasses_new_orgPath() {
        return matchedClasses_new_orgPath;
    }


    /**
     * Rebuild project structure using signatures.
     * 
     * @param unit mandatory target unit
     * @param sig Signature Object
     * @param dexHashCodeList
     */
    public void rebuildStructure(IDexUnit unit, Signature sig, DexHashcodeList dexHashCodeList) {
        getSignatures(sig);
        methodHashcodes = dexHashCodeList;
        logger.info("methodSizeBar " + dbMatcher.methodSizeBar);
        logger.info("matchedInstusPercentageBar " + dbMatcher.matchedInstusPercentageBar);

        // First Round using tight signature and loose signature
        logger.info("Signature matching 1 start...");
        final long startTime = System.currentTimeMillis();

        matchingVerOne(unit, sig);

        final long endTime = System.currentTimeMillis();
        logger.info("Signature matching 1 start completed! (Execution Time: " + (endTime - startTime) / 1000 + "s)");

        logger.info("******************************************************************");

        // Following Rounds using caller list
        logger.info("Signature matching 2 start...");
        final long startTime1 = System.currentTimeMillis();

        if(Thread.currentThread().isInterrupted()) {
            return;
        }

        matchingVerTwo(unit, sig);

        final long endTime1 = System.currentTimeMillis();
        logger.info("Signature matching 2 start completed! (Execution Time: " + (endTime1 - startTime1) / 1000 + "s)");

        // Move exceptional classes
        moveExceptionalClasses(unit);
        // Store all matched methods
        storeAllMatchedMethods_new_orgPath(unit);
        // Store all matched classes
        storeAllMatchedClasses_new_orgPath(unit);
    }

    private void matchingVerOne(IDexUnit unit, Signature sig) {
        dbMatcher.storeMatchedClassesAndMethods(unit, sig, methodHashcodes, true);
        // rename matched classes and methods
        renameMatchedClassesAndMethods(unit);
        // rename matched packages
        renameMatchedPackages(unit);

        // rename small methods
        renameSmallMethods(unit);

        SignatureHandler.loadAllCallerLists(unit, dbMatcher.getApkCallerLists(), dbMatcher.getMatchedClasses(),
                dbMatcher.getMatchedMethods());
    }

    private void matchingVerTwo(IDexUnit unit, Signature sig) {
        int matchedClassCount = dbMatcher.getMatchedClasses().size();
        logger.info("After matching ver 1 SIZE: " + dbMatcher.getMatchedClasses().size());
        while(true) {
            dbMatcher.storeMatchedClassesAndMethods(unit, sig, methodHashcodes, false);
            renameMatchedClassesAndMethods(unit);
            renameMatchedPackages(unit);
            renameSmallMethods(unit);
            logger.info("SIZE: " + dbMatcher.getMatchedClasses().size());
            if(dbMatcher.getMatchedClasses().size() == matchedClassCount) {
                break;
            }
            else {
                matchedClassCount = dbMatcher.getMatchedClasses().size();
            }
            SignatureHandler.loadAllCallerLists(unit, dbMatcher.getApkCallerLists(), dbMatcher.getMatchedClasses(),
                    dbMatcher.getMatchedMethods());
        }
    }

    private void getSignatures(Signature sig) {
        allLooseSignatures = sig.getAllLooseSignatures();
        allTightSignatures = sig.getAllTightSignatures();
    }

    private void renameMatchedClassesAndMethods(IDexUnit unit) {
        List<? extends IDexClass> classes = unit.getClasses();
        if(classes == null || classes.size() == 0) {
            return;
        }
        for(IDexClass eClass: classes) {
            if(modifiedClasses.contains(eClass.getIndex())) {
                continue;
            }
            if(dbMatcher.getMatchedClasses().containsKey(eClass.getIndex())) {
                // Rename class
                String classPath_sig = dbMatcher.getMatchedClasses().get(eClass.getIndex());
                String className = classPath_sig.substring(classPath_sig.lastIndexOf("/") + 1,
                        classPath_sig.length() - 1);
                StructureHandler.rename(unit, className, eClass.getItemId());
                MetadataGroupHandler.getCodeGroupClass(unit).setData(eClass.getSignature(false),
                        ItemClassIdentifiers.CODE_ROUTINE.getId());
                modifiedClasses.add(eClass.getIndex());

                // Rename methods
                List<? extends IDexMethod> methods = eClass.getMethods();
                if(methods == null || methods.size() == 0) {
                    continue;
                }

                if(dbMatcher.getMatchedMethods() == null || dbMatcher.getMatchedMethods().size() == 0) {
                    continue;
                }

                for(IDexMethod eMethod: methods) {
                    String temp = dbMatcher.getMatchedMethods().get(eMethod.getIndex());
                    if(temp != null) {
                        StructureHandler.rename(unit, temp, eMethod.getItemId());
                        MetadataGroupHandler.getCodeGroupMethod(unit).setData(eMethod.getSignature(false),
                                ItemClassIdentifiers.CODE_LIBRARY.getId());
                    }
                }
            }
        }
    }

    private void renameMatchedPackages(IDexUnit unit) {
        if(dbMatcher.getMatchedClasses() == null || dbMatcher.getMatchedClasses().size() == 0) {
            return;
        }
        for(Map.Entry<Integer, String> eClass: dbMatcher.getMatchedClasses().entrySet()) {
            int lastSlash = eClass.getValue().lastIndexOf("/");
            if(lastSlash >= 0) {
                String packagePath = eClass.getValue().substring(0, lastSlash) + ";";
                StructureHandler.createPackage(unit, packagePath);
                StructureHandler.moveClass(unit, packagePath, unit.getClass(eClass.getKey()).getItemId());
            }
        }
    }

    private void renameSmallMethods(IDexUnit unit) {
        Map<String, Integer> map = new HashMap<>();
        TreeMap<Integer, ArrayList<String>> treemap = new TreeMap<>(Collections.reverseOrder());
        for(int cIndex: dbMatcher.getMatchedClasses().keySet()) {
            IDexClass eClass = unit.getClass(cIndex);
            String classPath = eClass.getSignature(true);
            List<? extends IDexMethod> methods = eClass.getMethods();
            for(IDexMethod method: methods) {
                if(dbMatcher.getMatchedMethods().containsKey(method.getIndex())) {
                    continue;
                }
                map.clear();
                treemap.clear();
                IDexPrototype proto = unit.getPrototypes().get(method.getPrototypeIndex());
                String shorty = unit.getStrings().get(proto.getShortyIndex()).getValue();
                String mhash_tight = methodHashcodes.getTightHashcode(method);
                if(mhash_tight == null) {
                    continue;
                }
                List<String[]> sigs = allTightSignatures.get(mhash_tight);
                String methodName = null;
                if(sigs != null) {
                    methodName = findMethodName(map, treemap, sigs, shorty, classPath);
                }
                if(methodName == null) {
                    String mhash_loose = methodHashcodes.getLooseHashcode(method);
                    sigs = allLooseSignatures.get(mhash_loose);
                    if(sigs != null) {
                        methodName = findMethodName(map, treemap, sigs, shorty, classPath);
                    }
                }
                if(methodName != null) {
                    // TODO model break: should not modify here
                    dbMatcher.getMatchedMethods().put(method.getIndex(), methodName);
                    StructureHandler.rename(unit, methodName, method.getItemId());
                    MetadataGroupHandler.getCodeGroupMethod(unit).setData(method.getSignature(false),
                            ItemClassIdentifiers.CODE_LIBRARY.getId());
                }
            }
        }
    }

    private String findMethodName(Map<String, Integer> map, TreeMap<Integer, ArrayList<String>> treemap,
            List<String[]> sigs, String shorty, String classPath) {
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

    private void moveExceptionalClasses(IDexUnit unit) {
        List<? extends IDexClass> classes = unit.getClasses();
        if(classes == null || classes.size() == 0) {
            return;
        }
        for(IDexClass eClass: classes) {
            int classIndex = eClass.getIndex();
            if(!dbMatcher.getMatchedClasses().containsKey(classIndex)) {
                continue;
            }
            String classSigPath = dbMatcher.getMatchedClasses().get(classIndex);
            // If the class is located in the right package, continue
            if(classSigPath.equals(eClass.getSignature(true))) {
                continue;
            }
            String packageSigPath = classSigPath.substring(0, classSigPath.lastIndexOf("/")) + ";";
            StructureHandler.createPackage(unit, packageSigPath);
            StructureHandler.moveClass(unit, packageSigPath, eClass.getItemId());
        }
    }

    private void storeAllMatchedMethods_new_orgPath(IDexUnit unit) {
        for(int each: dbMatcher.getMatchedMethods().keySet()) {
            IDexMethod method = unit.getMethod(each);
            matchedMethods_new_orgPath.put(method.getSignature(true), method.getSignature(false));
        }
    }

    private void storeAllMatchedClasses_new_orgPath(IDexUnit unit) {
        for(int each: dbMatcher.getMatchedClasses().keySet()) {
            IDexClass eClass = unit.getClass(each);
            matchedClasses_new_orgPath.put(eClass.getSignature(true), eClass.getSignature(false));
        }
    }

    public DatabaseMatcher getDbMatcher() {
        return dbMatcher;
    }

}
