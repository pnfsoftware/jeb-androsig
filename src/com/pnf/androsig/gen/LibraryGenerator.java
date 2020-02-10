/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.gen;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.pnfsoftware.jeb.client.Licensing;
import com.pnfsoftware.jeb.core.IRuntimeProject;
import com.pnfsoftware.jeb.core.RuntimeProjectUtil;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.util.io.IO;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * @author Ruoxiao Wang, Cedric Lucas
 *
 */
public class LibraryGenerator {
    private static final ILogger logger = GlobalLog.getLogger(LibraryGenerator.class);

    private static final int androidSigFileVersion = 1;

    private static final boolean verbose = false;

    public static void generate(IRuntimeProject prj, File sigFolder, String libname, String classnameFilter) {
        StringBuilder sb = new StringBuilder();
        DexProcessor proc = new DexProcessor(classnameFilter);

        record(sb, ";comment=JEB signature file");
        record(sb, ";author=" + Licensing.user_name);
        record(sb, ";version=" + androidSigFileVersion);
        record(sb, ";libname=" + libname);

        // Process dex files
        List<IDexUnit> dexlist = RuntimeProjectUtil.findUnitsByType(prj, IDexUnit.class, false);
        List<String> lines = new ArrayList<>();
        for(IDexUnit dex: dexlist) {
            proc.processDex(dex);
            // Store all info to sb
            for(Map.Entry<Integer, String> each: proc.getSigMap().entrySet()) {
                if(proc.getAllCallerLists().containsKey(each.getKey())) {
                    lines.add(each.getValue() + ","
                            + transferIndexToName(dex, proc.getAllCallerLists().get(each.getKey())));
                }
                else {
                    lines.add(each.getValue() + ",");
                }
            }
            for(Map.Entry<Integer, String> each: proc.getHierarchyMap().entrySet()) {
                lines.add(each.getValue());
            }
        }

        // sort to have an absolute reference
        Collections.sort(lines);
        for(String line: lines) {
            record(sb, line);
        }

        if(proc.getMethodCount() >= 1) {
            File f = new File(sigFolder, sanitizeFilename(libname) + ".sig");
            logger.info("Saving signatures to file: %s", f);
            try {
                byte[] data = sb.toString().getBytes("UTF-8");
                if(!IO.writeFileSafe(f, data, true)) {
                    logger.error("Could not write signature file!");
                }
            }
            catch(UnsupportedEncodingException e) {
                logger.catching(e);
            }
        }
    }

    private static void record(StringBuilder sb, CharSequence s) {
        sb.append(s);
        sb.append('\n');

        if(verbose) {
            logger.info(s.toString());
        }
    }

    public static String sanitizeFilename(String s) {
        String s2 = "";
        for(int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            s2 += c == '-' || Character.isJavaIdentifierPart(c) ? c: '_';
        }
        return s2;
    }

    private static String transferIndexToName(IDexUnit dex, Map<Integer, Integer> inputs) {
        StringBuilder sb = new StringBuilder();
        for(Map.Entry<Integer, Integer> each: inputs.entrySet()) {
            sb.append(dex.getMethods().get(each.getKey()).getSignature(false)).append("=").append(each.getValue())
                    .append("|");
        }
        sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }

}
