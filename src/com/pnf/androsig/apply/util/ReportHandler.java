package com.pnf.androsig.apply.util;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.LibraryInfo;
import com.pnf.androsig.apply.model.StructureInfo;
import com.pnfsoftware.jeb.core.units.code.IInstruction;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

public class ReportHandler {
    private static final ILogger logger = GlobalLog.getLogger(ReportHandler.class);
    /**
     * Generate report.
     * 
     * @param unit mandatory target unit
     * @param struInfo StructureInfo Object which contains structure informations
     * @param sig Signature Object which contains signature informations
     */
    public static void generateRecord(IDexUnit unit, StructureInfo struInfo, DatabaseReference ref) {
        Map<Integer, String> matchedClasses = struInfo.getDbMatcher().getMatchedClasses();
        Map<Integer, String> matchedMethods = struInfo.getDbMatcher().getMatchedMethods();
        DecimalFormat df = new DecimalFormat("#.00");
        // Generate mapping file
        File mapping = new File(System.getProperty("java.io.tmpdir"), "androsig-mapping.txt");
        try(BufferedWriter writer = new BufferedWriter(new FileWriter(mapping));) {
            List<? extends IDexClass> classes = unit.getClasses();
            if(classes == null || classes.size() == 0) {
                return;
            }       
            for(IDexClass eClass: classes) {
                List<? extends IDexMethod> methods = eClass.getMethods();
                if(methods == null || methods.size() == 0)
                    continue;
                String classPath = matchedClasses.get(eClass.getIndex());
                String eClassSigFalse = eClass.getSignature(false);
                if(classPath == null) {
                    continue;
                }else {
                    writer.write(eClassSigFalse + " -> " + classPath + "\n");
                }
                double total = 0;
                double matched = 0;
                for(IDexMethod m: methods) {
                    if(!m.isInternal()) {
                        continue;
                    }
                    List<? extends IInstruction> inst = m.getInstructions();
                    if(inst == null) {
                        continue;
                    }
                    String methodPath = matchedMethods.get(m.getIndex());
                    String eMethodSigFalse = m.getSignature(false);
                    int instSize = inst.size();
                    total += instSize;
                    if(methodPath == null) {
                        continue;
                    }else {
                        matched += instSize;
                        writer.write("\t(" + instSize + ")" + eMethodSigFalse.split("->")[1] + " -> " + m.getSignature(true).split("->")[1] + "\n");
                    }
                }
                writer.write(df.format(matched / total) + "\n");
            }
        }
        catch(IOException e) {
            logger.error(e.toString());
        }

        // Generate report
        int allSignatureFileCount = ref.getAllSignatureFileCount();
        int allSignatureCount = struInfo.getDbMatcher().getSignatureMetrics().getAllSignatureCount();
        int allUsedSignatureFileCount = struInfo.getDbMatcher().getSignatureMetrics().getAllUsedSignatureFileCount();
        int allClassCount = unit.getClasses().size();
        int allMatchedClassCount = struInfo.getDbMatcher().getMatchedClasses().size();
        String matchedClassCountP = df.format((allMatchedClassCount * 100.0) / allClassCount);
        int allMatchedMethodCount = struInfo.getDbMatcher().getMatchedMethods().size();
        int allInterfaceAndEmptyClassCount = getInterfaceAndEmptyClassCount(unit);
        String interfaceAndEmptyClassCountP = df.format((allInterfaceAndEmptyClassCount * 100.0) / allClassCount);
        int allUnmatchedClassCount = allClassCount - allMatchedClassCount - allInterfaceAndEmptyClassCount;
        String unmatchedClassCountP = df.format((allUnmatchedClassCount * 100.0) / allClassCount);
        
        
        // Library distribution
        
        Map<String, LibraryInfo> libraryInfos = struInfo.getDbMatcher().getSignatureMetrics().getAllLibraryInfos();
        Map<String, Integer> libraryMap = new HashMap<>();
        for(String s : matchedClasses.values()) {
            LibraryInfo lib = libraryInfos.get(s);
            if(lib == null) {
                // reference to external class (not necessary in libs), matched by param matcher for example
                continue;
            }
            String libname = lib.getLibName();
            Integer count = libraryMap.get(libname);
            if(count == null) {
                count = 0;
            }
            libraryMap.put(libname, count + 1);
        }
        
        ArrayList<Map.Entry<String, Integer>> pairs = new ArrayList<>(libraryMap.entrySet());
        Collections.sort(pairs, new Comparator<Map.Entry<String, Integer>>() {
            @Override
            public int compare(Map.Entry<String, Integer> a, Map.Entry<String, Integer> b) {
                return Integer.parseInt(b.getValue().toString()) - Integer.parseInt(a.getValue().toString());
            }
        });
        
        
        File report = new File(System.getProperty("java.io.tmpdir"), "androsig-report.txt");
        try(BufferedWriter writer = new BufferedWriter(new FileWriter(report));) {
            writer.write("*************** Summary ***************\n");
            writer.write("Total number of signature files: " + allSignatureFileCount + "\n");
            writer.write("Total number of signatures: " + allSignatureCount + "\n");
            writer.write("Total number of used signature files: " + allUsedSignatureFileCount + "\n");
            writer.write("Total number of classes in app: " + allClassCount + "\n");
            writer.write("*************** Details ***************\n");   
            writer.write("Total number of matched classes: " + allMatchedClassCount + " (" + matchedClassCountP + "%)\n");
            writer.write("Total number of matched methods: " + allMatchedMethodCount + "\n");
            writer.write("Total number of interfaces and empty classes: " + allInterfaceAndEmptyClassCount + " (" + interfaceAndEmptyClassCountP + "%)\n");
            writer.write("Total number of unmatched classes: " + allUnmatchedClassCount + " (" + unmatchedClassCountP + "%)\n");
            writer.write("*************** Library Distribution ***************\n");
            for(Map.Entry<String, Integer> each : pairs) {
                writer.write(each.getKey() + ": " + each.getValue() + " (" + df.format((each.getValue() * 100.0) / allClassCount) + "%)\n");
            }
        }
        catch(IOException e) {
            logger.error(e.toString());
        }
        
        // Output to console
        logger.info("*************** Summary ***************");
        logger.info("Total number of signature files: " + allSignatureFileCount);
        logger.info("Total number of signatures: " + allSignatureCount);
        logger.info("Total number of used signature files: " + allUsedSignatureFileCount);
        logger.info("Total number of classes in app: " + allClassCount);
        logger.info("*************** Details ***************");   
        logger.info("Total number of matched classes: " + allMatchedClassCount + " (" + matchedClassCountP + "%)");
        logger.info("Total number of matched methods: " + allMatchedMethodCount);
        logger.info("Total number of interfaces and empty classes: " + allInterfaceAndEmptyClassCount + " (" + interfaceAndEmptyClassCountP + "%)");
        logger.info("Total number of unmatched classes: " + allUnmatchedClassCount + " (" + unmatchedClassCountP + "%)");
        logger.info("*************** Library Distribution ***************");
        for(Map.Entry<String, Integer> each : pairs) {
            logger.info(each.getKey() + ": " + each.getValue() + " (" + df.format((each.getValue() * 100.0) / allClassCount) + "%)");
        }
    }
    
    private static int getInterfaceAndEmptyClassCount(IDexUnit dex) {
        int count = 0;
        for(IDexClass each: dex.getClasses()) {
            if(each.getMethods() == null || each.getMethods().size() == 0) {
                count++;
            }
            else {
                boolean flag = true;
                for(IDexMethod eMethod: each.getMethods()) {
                    if(eMethod.getInstructions() != null && eMethod.getInstructions().size() != 0) {
                        flag = false;
                        break;
                    }
                }
                if(flag) {
                    count++;
                }
            }
        }
        return count;
    }
    
    /**
     * Serialization (For testing).
     * 
     * @param unit mandatory target unit
     * @param struInfo StructureInfo Object which contains structure informations
     */
    public static void serializeReport(IDexUnit unit, StructureInfo struInfo) {
        Mapping mapping = new Mapping();
        Map<String, String> classMap = mapping.getClassMap();
        Map<String, Map<String, String>> methodMap = mapping.getMethodMap();
        
        Map<Integer, String> matchedClasses = struInfo.getDbMatcher().getMatchedClasses();
        Map<Integer, String> matchedMethods = struInfo.getDbMatcher().getMatchedMethods();
        
        List<? extends IDexClass> classes = unit.getClasses();
        if(classes == null || classes.size() == 0) {
            return;
        }
        for(IDexClass eClass: classes) {
            List<? extends IDexMethod> methods = eClass.getMethods();
            if(methods == null || methods.size() == 0)
                continue;
            String classPath = matchedClasses.get(eClass.getIndex());
            if(classPath == null) {
                classMap.put(eClass.getSignature(false), "null");
            }else {
                classMap.put(eClass.getSignature(false), classPath);
            }
            Map<String, String> mMap = new HashMap<>();
            for(IDexMethod m: methods) {
                if(!m.isInternal()) {
                    continue;
                }
                String methodPath = matchedMethods.get(m.getIndex());
                if(methodPath == null) {
                    mMap.put(m.getSignature(false), "null");
                }else {
                    mMap.put(m.getSignature(false), m.getSignature(true));
                }
            }
            methodMap.put(eClass.getSignature(false), mMap);
        }
        
        try(ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(System.getProperty("user.home") + "/Desktop/newMapping.obj"))) {
            out.writeObject(mapping);
            out.close();
        }
        catch(FileNotFoundException e1) {
            e1.printStackTrace();
        }
        catch(IOException e1) {
            e1.printStackTrace();
        }
    }
    
    /**
     * Deserialization (For testing).
     * 
     * @param unit mandatory target unit
     * @param struInfo StructureInfo Object which contains structure informations
     */
    public static void deserializeReport(IDexUnit unit, StructureInfo struInfo) {
        Mapping baseMapping = null;
        Mapping newMapping = null;
        
        try(ObjectInputStream inBaseMapping = new ObjectInputStream(new FileInputStream(System.getProperty("user.home") + "/Desktop/baseMapping.obj"));
                ObjectInputStream inNewMapping = new ObjectInputStream(new FileInputStream(System.getProperty("user.home") + "/Desktop/newMapping.obj"))) {
            baseMapping = (Mapping)inBaseMapping.readObject();
            newMapping = (Mapping)inNewMapping.readObject();
        }
        catch(Exception e1) {
            logger.catching(e1);
            e1.printStackTrace();
        }
        if(baseMapping == null) {
            logger.info("it is null");
        }
        Map<String, String> baseClassMap = baseMapping.getClassMap();
        Map<String, Map<String, String>> baseMethodMap = baseMapping.getMethodMap();
        Map<String, String> newClassMap = newMapping.getClassMap();
        Map<String, Map<String, String>> newMethodMap = newMapping.getMethodMap();
        // Comparison
        File baseOnlyMatchFile = new File(System.getProperty("user.home") + "/Desktop", "baseOnlyMatch.txt");
        File newOnlyMatchFile = new File(System.getProperty("user.home") + "/Desktop", "newOnlyMatch.txt");
        File bothMatchFile = new File(System.getProperty("user.home") + "/Desktop", "bothMatch.txt");
        try(BufferedWriter writerBase = new BufferedWriter(new FileWriter(baseOnlyMatchFile));
                BufferedWriter writerNew = new BufferedWriter(new FileWriter(newOnlyMatchFile));
                BufferedWriter writerBoth = new BufferedWriter(new FileWriter(bothMatchFile));) {
            for(Map.Entry<String, String> entry : baseClassMap.entrySet()) {
                boolean baseFlag = false, newFlag = false, bothFlag = false;        
                String baseClassPath = entry.getValue();
                String newClassPath = newClassMap.get(entry.getKey());
                // Both are unmatched
                if(baseClassPath.equals("null") && newClassPath.equals("null")) {
                    continue;
                }
                if(!baseClassPath.equals("null") && !newClassPath.equals("null")) {
                    bothFlag = true;
                    if(baseClassPath.equals(newClassPath)) {
                        writerBoth.write(entry.getKey() + " -------> " + baseClassPath + "\n");
                    }else {
                        writerBoth.write("base: " + entry.getKey() + " -------> " + baseClassPath + "\n");
                        writerBoth.write("new: " + entry.getKey() + " -------> " + newClassPath + "\n");
                    }
                }else {
                    if(!baseClassPath.equals("null")) {
                        writerBase.write(entry.getKey() + " -------> " + baseClassPath + "\n");
                        baseFlag = true;
                    }
                    if(!newClassPath.equals("null")) {
                        writerNew.write(entry.getKey() + " -------> " + newClassPath + "\n");
                        newFlag = true;
                    }
                }
                Map<String, String> baseMMap = baseMethodMap.get(entry.getKey());
                Map<String, String> newMMap = newMethodMap.get(entry.getKey());
                if(bothFlag) {
                    for(Map.Entry<String, String> entry1 : baseMMap.entrySet()) {
                        String baseMPath = entry1.getValue();
                        String newMPath = newMMap.get(entry1.getKey());
                        if(baseMPath.equals("null") && newMPath.equals("null")) {
                            continue;
                        }
                        if(baseMPath.equals(newMPath)) {
                            writerBoth.write("\torg: " + entry1.getKey() + "\n");
                            writerBoth.write("\tmat: " + baseMPath + "\n");
                        }else {
                            writerBoth.write("\t*[base]org: " + entry1.getKey() + "\n");
                            writerBoth.write("\t*[base]mat: " + baseMPath + "\n");
                            writerBoth.write("\t*[new]org: " + entry1.getKey() + "\n");
                            writerBoth.write("\t*[new]mat: " + newMPath + "\n");
                        }
                    }
                }
                if(baseFlag) {
                    for(Map.Entry<String, String> entry1 : baseMMap.entrySet()) {
                        String baseMPath = entry1.getValue();
                        if(baseMPath.equals("null")) {
                            continue;
                        }
                        writerBase.write("\torg: " + entry1.getKey() + "\n");
                        writerBase.write("\tmat: " + baseMPath + "\n");        
                    }
                }
                if(newFlag) {
                    for(Map.Entry<String, String> entry1 : newMMap.entrySet()) {
                        String newMPath = newMMap.get(entry1.getKey());
                        if(newMPath.equals("null")) {
                            continue;
                        }
                        writerNew.write("\torg: " + entry1.getKey() + "\n");
                        writerNew.write("\tmat: " + newMPath + "\n");
                    }
                }
            }
        }
        catch(IOException e) {
            e.printStackTrace();
        }
    }
}
