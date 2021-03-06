package com.pnf.androsig.apply.util;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;

import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.LibraryInfo;
import com.pnf.androsig.apply.model.StructureInfo;
import com.pnfsoftware.jeb.core.units.code.IInstruction;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.util.format.Strings;
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
        File mappingMini = new File(System.getProperty("java.io.tmpdir"), "androsig-mapping-mini.txt");
        File mappingTiny = new File(System.getProperty("java.io.tmpdir"), "androsig-mapping-tiny.txt");
        try(BufferedWriter writer = new BufferedWriter(new FileWriter(mapping));
                BufferedWriter writerMini = new BufferedWriter(new FileWriter(mappingMini));
                BufferedWriter writerTiny = new BufferedWriter(new FileWriter(mappingTiny));) {
            List<? extends IDexClass> classes = unit.getClasses();
            if(classes == null || classes.size() == 0) {
                return;
            }
            Map<String, IDexClass> classesMapped = new TreeMap<>();
            for(IDexClass eClass: classes) {
                String classPath = matchedClasses.get(eClass.getIndex());
                if(classPath != null) {
                    classesMapped.put(classPath, eClass);
                }
            }
            for(Entry<String, IDexClass> cl: classesMapped.entrySet()) {
                String eClassSigFalse = cl.getValue().getSignature(false);
                String classMapping = eClassSigFalse + " -> " + cl.getKey() + "\n";
                writer.write(classMapping);
                boolean classWritten = false;
                boolean tinyClassWritten = false;
                boolean classDifferent = !eClassSigFalse.equals(cl.getKey());
                if(classDifferent) {
                    classWritten = true;
                    writerMini.write(classMapping);
                    if(!isSamePackage(eClassSigFalse, cl.getKey(), 2)) {
                        tinyClassWritten = true;
                        writerTiny.write(classMapping);
                    }
                }
                List<? extends IDexMethod> methods = cl.getValue().getMethods();
                if(methods == null || methods.size() == 0)
                    continue;
                double total = 0;
                double matched = 0;
                for(IDexMethod m: methods) {
                    if(!m.isInternal()) {
                        continue;
                    }
                    List<? extends IInstruction> inst = m.getInstructions();
                    String methodPath = matchedMethods.get(m.getIndex());
                    String eMethodSigFalse = m.getSignature(false);
                    int instSize = inst == null ? 0: inst.size();
                    total += instSize;
                    if(methodPath == null) {
                        continue;
                    }else {
                        matched += instSize;
                        String mMethodName = eMethodSigFalse.split("->")[1];
                        String mNewMethodName = m.getSignature(true).split("->")[1];
                        String mMapping = "\t(" + instSize + ")" + mMethodName + " -> " + mNewMethodName + "\n";
                        writer.write(mMapping);
                        if(classDifferent || !mMethodName.equals(mNewMethodName)) {
                            if(!classWritten) {
                                classWritten = true;
                                writerMini.write(classMapping);
                            }
                            writerMini.write(mMapping);
                            if(tinyClassWritten) {
                                writerTiny.write(mMapping);
                            }
                        }
                    }
                }
                String coverage = df.format(total == 0 ? 0: (matched / total)) + "\n";
                writer.write(coverage);
                if(classWritten) {
                    writerMini.write(coverage);
                }
                if(tinyClassWritten) {
                    writerTiny.write(coverage);
                }
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
        Map<LibraryInfo, Integer> libraryMap = new HashMap<>();
        for(String s : matchedClasses.values()) {
            LibraryInfo lib = libraryInfos.get(s);
            if(lib == null) {
                // reference to external class (not necessary in libs), matched by param matcher for example
                continue;
            }
            Integer count = libraryMap.get(lib);
            if(count == null) {
                count = 0;
            }
            libraryMap.put(lib, count + 1);
        }
        
        List<Map.Entry<LibraryInfo, Integer>> pairs = new ArrayList<>(libraryMap.entrySet());
        Collections.sort(pairs, new Comparator<Map.Entry<LibraryInfo, Integer>>() {
            @Override
            public int compare(Map.Entry<LibraryInfo, Integer> a, Map.Entry<LibraryInfo, Integer> b) {
                return Integer.parseInt(b.getValue().toString()) - Integer.parseInt(a.getValue().toString());
            }
        });
        
        StringBuilder stb = new StringBuilder();
        stb.append("*************** Summary ***************\n");
        stb.append("Total number of signature files: ").append(allSignatureFileCount).append("\n");
        stb.append("Total number of signatures: ").append(allSignatureCount).append("\n");
        stb.append("Total number of used signature files: ").append(allUsedSignatureFileCount).append("\n");
        stb.append("Total number of classes in app: ").append(allClassCount).append("\n");
        stb.append("*************** Details ***************\n");
        stb.append("Total number of matched classes: ").append(allMatchedClassCount).append(" (")
                .append(matchedClassCountP).append("%)\n");
        stb.append("Total number of matched methods: ").append(allMatchedMethodCount).append("\n");
        stb.append("Total number of interfaces and empty classes: ").append(allInterfaceAndEmptyClassCount).append(" (")
                .append(interfaceAndEmptyClassCountP).append("%)\n");
        stb.append("Total number of unmatched classes: ").append(allUnmatchedClassCount)
                .append(" (").append(unmatchedClassCountP).append("%)\n");
        stb.append("*************** Library Distribution ***************\n");
        List<String> pairsUnVersionned = new ArrayList<>();
        int maxLength = 0;
        for(Entry<LibraryInfo, Integer> each: pairs) {
            String libLine = each.getKey().getLibName() + ": " + each.getValue() + " ("
                    + df.format((each.getValue() * 100.0) / allClassCount) + "%)";
            maxLength = libLine.length() > maxLength ? libLine.length(): maxLength;
            pairsUnVersionned.add(libLine);
        }
        for(int i = 0; i < pairs.size(); i++) {
            Entry<LibraryInfo, Integer> libInfo = pairs.get(i);
            String libLine = pairsUnVersionned.get(i);
            stb.append(libLine);
            Set<String> versionSet = libInfo.getKey().getVersions();
            if(versionSet != null && !versionSet.isEmpty()) {
                stb.append(Strings.spaces(maxLength - libLine.length() + 4));
                stb.append("versions: ").append(Strings.join(", ", versionSet));
            }
            stb.append("\n");
        }
        String reportContent = stb.toString();
        File report = new File(System.getProperty("java.io.tmpdir"), "androsig-report.txt");
        try(BufferedWriter writer = new BufferedWriter(new FileWriter(report));) {
            writer.write(reportContent);
        }
        catch(IOException e) {
            logger.error(e.toString());
        }
        
        // Output to console
        logger.info(reportContent);
    }
    
    private static boolean isSamePackage(String c1, String c2, int depth) {
        //c2 = c2.replace("Lretrofit2/", "Lb/");
        //c2 = c2.replace("Lokio/", "La/");
        String[] c1Array = c1.split("/");
        String[] c2Array = c2.split("/");
        if(c1Array.length == c2Array.length && c1Array.length > 1 && c1Array.length <= depth) {
            depth = c1Array.length - 1;
        }
        if(c1Array.length > depth && c2Array.length > depth) {
            for(int i = 0; i < depth; i++) {
                if(!c1Array[i].equals(c2Array[i])) {
                    return false;
                }
            }
            return true;
        }
        return false;
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
}
