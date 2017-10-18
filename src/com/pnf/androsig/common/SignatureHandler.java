package com.pnf.androsig.common;

import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.pnfsoftware.jeb.core.IEnginesContext;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDalvikInstruction;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDalvikInstructionParameter;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexCodeItem;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethodData;
import com.pnfsoftware.jeb.util.format.Formatter;

public class SignatureHandler {
    /**
     * Generate tight hashcode for each method.
     * Combine all instructions of the method to a string and use SHA-256 hash function to generate hashcode.
     * 
     * @param ci IDexCodeItem of the method
     * @return tight hashcode
     */
    public static String generateTightHashcode(IDexCodeItem ci) {
        StringBuilder sig = new StringBuilder();
        for(IDalvikInstruction insn: ci.getInstructions()) {
            sig.append(insn.getMnemonic() + ":");
            // note: array- and switch-data are disregarded
            for(IDalvikInstructionParameter param: insn.getParameters()) {
                int pt = param.getType();
                sig.append(String.format("%d,", pt));
                if(pt == IDalvikInstruction.TYPE_IDX || pt == IDalvikInstruction.TYPE_REG) {
                    sig.append("x,"); // disregard pool indexes;
                }
                else {
                    sig.append(String.format("%d,", param.getValue()));
                }
            }
            sig.append(" ");
        }
        byte[] h;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            h = md.digest(sig.toString().getBytes());
        }
        catch(NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        sig = null;
        return Formatter.byteArrayToHexString(h).toLowerCase();
    }

    /**
     * Generate loose hashcode for each method.
     * Combine specific instructions of the method to a string and use SHA-256 hash function to generate hashcode.
     * 
     * Following kinds of instructions need extra processing:
     * (1) Instruction contains "move" and "const" will be excluded.
     * (2) Instruction contains "goto"(goto, goto/16, goto/32) will only record "goto".
     * (3) Instruction contains "/"(add-int/2addr, div-long/2addr ...) will only record the part before "/" (eg: add-int/2addr -> add-int).
     * 
     * @param ci IDexCodeItem of the method
     * @return loose hashcode
     */
    public static String generateLooseHashcode(IDexCodeItem ci) {
        StringBuilder sig = new StringBuilder();
        for(IDalvikInstruction insn: ci.getInstructions()) {
            if(insn.getMnemonic().contains("move") || insn.getMnemonic().contains("const")) {
                continue;
            }
            boolean flag = false;
            if(insn.getMnemonic().contains("goto")) {
                sig.append("goto:");
            }
            else if(insn.getMnemonic().contains("/")) {
                sig.append(insn.getMnemonic().split("/")[0] + ":");
                flag = true;
            }
            else {
                sig.append(insn.getMnemonic() + ":");
            }
            // note: array- and switch-data are disregarded
            for(IDalvikInstructionParameter param: insn.getParameters()) {
                int pt = param.getType();
                sig.append(String.format("%d,", pt));
            }
            if(flag) {
                sig.append(String.format("%d,", insn.getParameters()[0].getType()));
            }

            sig.append(" ");
        }

        byte[] h;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            h = md.digest(sig.toString().getBytes());
        }
        catch(NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        sig = null;
        return Formatter.byteArrayToHexString(h).toLowerCase();
    }
    
    /**
     * Generate caller list based on methods relationship and store them to hashmap.
     * eg: method1 call method2 2 times and method3 4 times
     *     store:
     *          key: method2.getIndex()     value: (method1.getIndex(), 2 times)
     *          key: method3.getIndex()     value: (method1.getIndex(), 4 times)
     *     to hashmap (key is the method index which is called, the value is also a hashmap, the key is caller method index, the value is call times).
     * 
     * @param unit mandatory target unit
     * @param allCallerLists hashmap used to store all caller list
     * @param matchedClasses hashmap used to store all matched classes (This parameter is used to filter the unmatched classes. If this function is called from AndroidSigGenPlugin, set it to null)
     * @param matchedMethods hashmap used to store all matched methods (This parameter is used to filter the unmatched methods. If this function is called from AndroidSigGenPlugin, set it to null)
     */
    public static void loadAllCallerLists(IDexUnit unit, Map<Integer, Map<Integer, Integer>> allCallerLists, Map<Integer, String> matchedClasses, Map<Integer, String> matchedMethods) {
        allCallerLists.clear();
        List<? extends IDexClass> classes = unit.getClasses();
        if(classes == null || classes.size() == 0) {
            return;
        }
        for(IDexClass eClass: classes) {
            List<? extends IDexMethod> methods = eClass.getMethods();
            if(methods == null || methods.size() == 0)
                continue;
            if(matchedClasses != null) {
                if(!matchedClasses.containsKey(eClass.getIndex())) {
                    continue;
                }
            }
            for(IDexMethod m: methods) {
                if(!m.isInternal()) {
                    continue;
                }
                if(matchedMethods != null) {
                    if(!matchedMethods.containsKey(m.getIndex())) {
                        continue;
                    }
                }
                IDexMethodData md = m.getData();
                if(md == null) {
                    continue;
                }
                IDexCodeItem ci = md.getCodeItem();
                if(ci == null) {
                    continue;
                }
                for(IDalvikInstruction insn: ci.getInstructions()) {
                    if(!insn.getMnemonic().contains("invoke")) {
                        continue;
                    }
                    for(IDalvikInstructionParameter param: insn.getParameters()) {
                        if(param.getType() == IDalvikInstruction.TYPE_IDX) {
                            int poolIndex = insn.getParameterIndexType();
                            if(poolIndex == IDalvikInstruction.INDEX_TO_METHOD) {
                                int paraValue = (int)param.getValue();
                                if(paraValue > unit.getMethods().size()) {
                                    continue;
                                }
                                // Store method info
                                Map<Integer, Integer> temp = allCallerLists.get(paraValue);
                                int methodIndex = m.getIndex();
                                if(temp != null) {
                                    Integer times = temp.get(methodIndex);
                                    if(times != null) {
                                        temp.put(methodIndex, times + 1);
                                    }
                                    else {
                                        temp.put(methodIndex, 1);
                                    }
                                }
                                else {
                                    HashMap<Integer, Integer> temp1 = new HashMap<Integer, Integer>();
                                    temp1.put(methodIndex, 1);
                                    allCallerLists.put(paraValue, temp1);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    /**
     * Get the signature folder.
     * 
     * @param engctx engine context
     * @return Signature folder File Object
     * @throws IOException
     */
    public static File getSignaturesFolder(IEnginesContext engctx) throws IOException {
        String pluginFolderPath = engctx.getDataProvider().getPluginStore().getStoreLocation();
        if(pluginFolderPath == null) {
            throw new IOException("Cannot retrieve the plugins folder!");
        }
        File dir = new File(pluginFolderPath, "android_sigs");
        if(!dir.exists()) {
            if(!dir.mkdirs()) {
                throw new IOException("Cannot create the Android Signatures folder: " + dir.getPath());
            }
        }
        else if(!dir.isDirectory()) {
            throw new IOException("The Android Signatures folder location is occupied: " + dir.getPath());
        }
        return dir;
    }
}
