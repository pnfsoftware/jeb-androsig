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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.pnf.androsig.apply.matcher.DatabaseMatcherFactory;
import com.pnf.androsig.apply.matcher.IDatabaseMatcher;
import com.pnf.androsig.apply.util.DexUtilLocal;
import com.pnf.androsig.apply.util.MetadataGroupHandler;
import com.pnf.androsig.apply.util.StructureHandler;
import com.pnfsoftware.jeb.core.output.ItemClassIdentifiers;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
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

    // Modified classes
    private Set<Integer> modifiedClasses = new HashSet<>();

    private StructureResult structureResult = new StructureResult();

    private IDatabaseMatcher dbMatcher;

    public StructureInfo(Map<String, String> executionOptions, DatabaseReference ref) {
        dbMatcher = DatabaseMatcherFactory.build(executionOptions, ref);
    }

    /**
     * Rebuild project structure using signatures.
     * 
     * @param unit mandatory target unit
     * @param sig Signature Object
     * @param dexHashCodeList
     */
    public void rebuildStructure(IDexUnit unit, DexHashcodeList dexHashCodeList) {
        logger.info("methodSizeBar " + dbMatcher.getParameters().methodSizeBar);
        logger.info("matchedInstusPercentageBar " + dbMatcher.getParameters().matchedInstusPercentageBar);

        // First Round using tight signature and loose signature
        logger.info("Signature matching 1 start...");
        final long startTime = System.currentTimeMillis();

        matchingVerOne(unit, dexHashCodeList);

        final long endTime = System.currentTimeMillis();
        logger.info("Signature matching 1 start completed! (Execution Time: " + (endTime - startTime) / 1000 + "s)");

        logger.info("******************************************************************");

        // Following Rounds using caller list
        logger.info("Signature matching 2 start...");
        final long startTime1 = System.currentTimeMillis();

        if(Thread.currentThread().isInterrupted()) {
            return;
        }

        matchingVerTwo(unit, dexHashCodeList);

        final long endTime1 = System.currentTimeMillis();
        logger.info("Signature matching 2 start completed! (Execution Time: " + (endTime1 - startTime1) / 1000 + "s)");
        if(logger.getEnabledLevel() >= GlobalLog.LEVEL_DEBUG) {
            List<String> mapped = new ArrayList<>(dbMatcher.getMatchedClasses().values());
            Collections.sort(mapped);
            for(String cl: mapped) {
                logger.debug("Mapped class: %s", cl);
            }
        }

        // Move exceptional classes
        moveExceptionalClasses(unit);
        // Store all matched methods
        structureResult.storeAllMatchedMethods_new_orgPath(unit, dbMatcher.getMatchedMethods());
        // Store all matched classes
        structureResult.storeAllMatchedClasses_new_orgPath(unit, dbMatcher.getMatchedClasses());
    }

    private void matchingVerOne(IDexUnit unit, DexHashcodeList dexHashCodeList) {
        dbMatcher.storeMatchedClassesAndMethods(unit, dexHashCodeList, true);
        // rename matched classes and methods
        renameMatchedClassesAndMethods(unit);
        // rename matched packages
        renameMatchedPackages(unit);

        Map<Integer, String> newClasses = dbMatcher.postProcessRenameClasses(unit, dexHashCodeList, true);
        Map<Integer, String> newMethods = dbMatcher.postProcessRenameMethods(unit, dexHashCodeList, true);
        postProcess(unit, newClasses, newMethods);

        //SignatureHandler.loadAllCallerLists(unit, dbMatcher.getApkCallerLists(), dbMatcher.getMatchedClasses(),
        //        dbMatcher.getMatchedMethods());
    }

    private void matchingVerTwo(IDexUnit unit, DexHashcodeList dexHashCodeList) {
        int matchedClassCount = dbMatcher.getMatchedClasses().size();
        logger.info("After matching ver 1 SIZE: " + dbMatcher.getMatchedClasses().size());
        while(true) {
            dbMatcher.storeMatchedClassesAndMethods(unit, dexHashCodeList, false);
            renameMatchedClassesAndMethods(unit);
            renameMatchedPackages(unit);
            Map<Integer, String> newClasses = dbMatcher.postProcessRenameClasses(unit, dexHashCodeList, false);
            Map<Integer, String> newMethods = dbMatcher.postProcessRenameMethods(unit, dexHashCodeList, false);
            postProcess(unit, newClasses, newMethods);

            logger.info("SIZE: " + dbMatcher.getMatchedClasses().size());
            if(dbMatcher.getMatchedClasses().size() == matchedClassCount) {
                break;
            }
            else {
                matchedClassCount = dbMatcher.getMatchedClasses().size();
            }
            //SignatureHandler.loadAllCallerLists(unit, dbMatcher.getApkCallerLists(), dbMatcher.getMatchedClasses(),
            //        dbMatcher.getMatchedMethods());
        }
    }

    private void postProcess(IDexUnit unit, Map<Integer, String> newClasses, Map<Integer, String> newMethods) {
        for(Entry<Integer, String> each: newClasses.entrySet()) {
            IDexClass eClass = unit.getClass(each.getKey());
            StructureHandler.rename(unit, each.getValue(), eClass.getItemId());
            MetadataGroupHandler.getCodeGroupClass(unit).setData(eClass.getSignature(false),
                    ItemClassIdentifiers.CODE_ROUTINE.getId());
        }

        for(Entry<Integer, String> each: newMethods.entrySet()) {
            IDexMethod method = unit.getMethod(each.getKey());
            String temp = each.getValue();
            if(temp != null && !method.getName(true).equals(temp)) {
                StructureHandler.rename(unit, each.getValue(), method.getItemId());
                MetadataGroupHandler.getCodeGroupMethod(unit).setData(method.getSignature(false),
                        ItemClassIdentifiers.CODE_LIBRARY.getId());
            }
        }
    }

    private void renameMatchedClassesAndMethods(IDexUnit unit) {
        List<? extends IDexClass> classes = unit.getClasses();
        if(classes == null || classes.size() == 0) {
            return;
        }
        for(IDexClass eClass: classes) {
            if(!dbMatcher.getMatchedClasses().containsKey(eClass.getIndex())) {
                continue;
            }
            if(!modifiedClasses.contains(eClass.getIndex())) {
                // Rename class
                String classPath_sig = dbMatcher.getMatchedClasses().get(eClass.getIndex());
                String className = classPath_sig.substring(classPath_sig.lastIndexOf("/") + 1,
                        classPath_sig.length() - 1);
                int innerClassStartName = className.lastIndexOf("$");
                if(innerClassStartName >= 0) {
                    className = className.substring(innerClassStartName + 1);
                }
                if(innerClassStartName >= 0 && DexUtilLocal.isAnonymous(eClass)) {
                    // anonymous class: do not rename, otherwise we will have strange behavior
                    // since anonymous class _keeps_ its internal index in addition to its name
                    // (will maybe be fixed in future versions)
                }
                else {
                    StructureHandler.rename(unit, className, eClass.getItemId());
                }
                MetadataGroupHandler.getCodeGroupClass(unit).setData(eClass.getSignature(false),
                        ItemClassIdentifiers.CODE_ROUTINE.getId());
                modifiedClasses.add(eClass.getIndex());
            }

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
                if(temp != null && !eMethod.getName(true).equals(temp)) {
                    StructureHandler.rename(unit, temp, eMethod.getItemId());
                    MetadataGroupHandler.getCodeGroupMethod(unit).setData(eMethod.getSignature(false),
                            ItemClassIdentifiers.CODE_LIBRARY.getId());
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
            if(lastSlash >= 0 && !eClass.getValue().contains("$")) {
                String packagePath = eClass.getValue().substring(0, lastSlash) + ";";
                StructureHandler.createPackage(unit, packagePath);
                StructureHandler.moveClass(unit, packagePath, unit.getClass(eClass.getKey()).getItemId());
            }
        }
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
            if(classSigPath.equals(eClass.getSignature(true)) || classSigPath.contains("$")) {
                continue;
            }
            String packageSigPath = classSigPath.substring(0, classSigPath.lastIndexOf("/")) + ";";
            StructureHandler.createPackage(unit, packageSigPath);
            StructureHandler.moveClass(unit, packageSigPath, eClass.getItemId());
        }
    }

    public IDatabaseMatcher getDbMatcher() {
        return dbMatcher;
    }

    public IStructureResult getStructureResult() {
        return structureResult;
    }

}
