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

package com.pnf.androsig.gen;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.pnf.androsig.common.SignatureHandler;
import com.pnfsoftware.jeb.client.Licensing;
import com.pnfsoftware.jeb.core.IEnginesContext;
import com.pnfsoftware.jeb.core.IEnginesPlugin;
import com.pnfsoftware.jeb.core.IOptionDefinition;
import com.pnfsoftware.jeb.core.IPluginInformation;
import com.pnfsoftware.jeb.core.IRuntimeProject;
import com.pnfsoftware.jeb.core.OptionDefinition;
import com.pnfsoftware.jeb.core.PluginInformation;
import com.pnfsoftware.jeb.core.RuntimeProjectUtil;
import com.pnfsoftware.jeb.core.Version;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexCodeItem;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethodData;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexPrototype;
import com.pnfsoftware.jeb.util.IO;
import com.pnfsoftware.jeb.util.Strings;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * Generate generic simple signatures for Android library methods. This plugin was ported from JEB1.
 * It is in no means intended to be used in professional systems: it is simply a POC show-casing how
 * easy it is to build a signing+matching system for DEX bytecode. It could easily be improved and
 * extended for all ICodeUnit in general, instead of being limited to IDexUnit.
 * <p>
 * This is the first part of a 2-part plugin. Second part: AndroidSigApplyPlugin.
 * <p>
 * ********************* Version 2 *********************
 * <p>
 * How to use:
 * <ul>
 * <li>Load a DEX file (UI, headless client, other)</li>
 * <li>Execute the plugin, optionally providing a filter regex and library name
 * </p>
 * <li>Signature file goes to <code>[JEB_PLUGINS]/android_sigs/[libname].sig</code></li> <li>To
 * apply sigs on unknown files, execute the AndroidSigApplyPlugin plugin</li> </ul>
 * 
 * @author Ruoxiao Wang
 */
public class AndroidSigGenPlugin implements IEnginesPlugin {
    private static final ILogger logger = GlobalLog.getLogger(AndroidSigGenPlugin.class);

    private static final int androidSigFileVersion = 1;

    private static final boolean verbose = false;

    @Override
    public IPluginInformation getPluginInformation() {
        return new PluginInformation("Android Code Signature Generator",
                "Generate generic signatures to identify Android libraries (Ported from JEB1)", "PNF Software",
                Version.create(1, 0), Version.create(2, 2, 1), null);
    }

    @Override
    public List<? extends IOptionDefinition> getExecutionOptionDefinitions() {
        return Arrays.asList(new OptionDefinition("libname", "Library name"));
    }

    @Override
    public void dispose() {
    }

    @Override
    public void execute(IEnginesContext context) {
        execute(context, null);
    }

    private StringBuilder sb;
    private int methodCount;

    private Map<Integer, Map<Integer, Integer>> allCallerLists;
    private Map<Integer, String> sigMap;

    @Override
    public void execute(IEnginesContext engctx, Map<String, String> executionOptions) {
        IRuntimeProject prj = engctx.getProject(0);
        if(prj == null) {
            logger.info("There is no opened project");
            return;
        }

        // reset attributes
        sb = new StringBuilder();
        methodCount = 0;
        allCallerLists = new HashMap<>();
        sigMap = new HashMap<>();

        String libname = executionOptions.get("libname");
        if(Strings.isBlank(libname)) {
            libname = prj.getName();
        }

        record(";comment=JEB signature file");
        record(";author=" + Licensing.user_name);
        record(";version=" + androidSigFileVersion);
        record(";libname=" + libname);

        // Process dex files
        List<IDexUnit> dexlist = RuntimeProjectUtil.findUnitsByType(prj, IDexUnit.class, false);
        for(IDexUnit dex: dexlist) {
            processDex(dex);
            SignatureHandler.loadAllCallerLists(dex, allCallerLists, null, null);
            // Store all info to sb
            for(Map.Entry<Integer, String> each: sigMap.entrySet()) {
                if(allCallerLists.containsKey(each.getKey())) {
                    record(each.getValue() + "," + transferIndexToName(dex, allCallerLists.get(each.getKey())));
                }
                else {
                    record(each.getValue() + ",null");
                }
            }
        }

        if(methodCount >= 1) {
            File sigFolder = SignatureHandler.getSignaturesFolder(engctx);

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

    private void record(String s) {
        sb.append(s);
        sb.append('\n');

        if(verbose) {
            logger.info(s);
        }
    }

    private String sanitizeFilename(String s) {
        String s2 = "";
        for(int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            s2 += c == '-' || Character.isJavaIdentifierPart(c) ? c: '_';
        }
        return s2;
    }

    private String transferIndexToName(IDexUnit dex, Map<Integer, Integer> inputs) {
        StringBuilder sb = new StringBuilder();
        for(Map.Entry<Integer, Integer> each: inputs.entrySet()) {
            sb.append(dex.getMethods().get(each.getKey()).getSignature(false) + "=" + each.getValue() + "|");
        }
        sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }

    private boolean processDex(IDexUnit dex) {
        if(!dex.isProcessed()) {
            if(!dex.process()) {
                return false;
            }
        }
        List<? extends IDexClass> classes = dex.getClasses();
        if(classes == null || classes.size() == 0) {
            logger.info("No classes in current project");
            return false;
        }
        for(IDexClass eClass: classes) {
            List<? extends IDexMethod> methods = eClass.getMethods();
            if(methods == null || methods.size() == 0) {
                continue;
            }
            for(IDexMethod m: methods) {
                if(!m.isInternal()) {
                    continue;
                }

                IDexMethodData md = m.getData();
                if(md == null) {
                    continue;
                }

                String mhash_tight = new String();
                String mhash_loose = new String();
                int opcount = 0;

                IDexCodeItem ci = md.getCodeItem();
                if(ci == null) {
                    mhash_tight = "null";
                    mhash_loose = "null";
                }
                else {
                    mhash_tight = SignatureHandler.generateTightHashcode(ci); // Get tight hashcode
                    mhash_loose = SignatureHandler.generateLooseHashcode(ci); // Get loose hashcode
                    opcount = ci.getInstructions().size();
                }
                if(mhash_tight == null || mhash_loose == null) {
                    continue;
                }
                String classfullname = dex.getTypes().get(m.getClassTypeIndex()).getSignature(true);
                String methodname = m.getName(true);
                //m.getp
                IDexPrototype proto = dex.getPrototypes().get(m.getPrototypeIndex());
                String shorty = proto.getShorty();
                String prototypes = proto.generate(false);

                String s = String.format("%s,%s,%s,%s,%d,%s,%s", classfullname, methodname, shorty, prototypes,
                        opcount, mhash_tight, mhash_loose);
                sigMap.put(m.getIndex(), s);

                methodCount++;
            }
        }
        return true;
    }
}