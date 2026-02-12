
using System;
using System.Runtime.InteropServices;
using System.Reflection;
class Program
{
    // FSO CLSID
    static readonly Guid CLSID_FSO = new Guid("0D43FE01-F093-11CF-8940-00A0C9054228");

    // Common interface IIDs
    static readonly Guid IID_IUnknown = new Guid("00000000-0000-0000-C000-000000000046");
    static readonly Guid IID_IDispatch = new Guid("00020400-0000-0000-C000-000000000046");
    static readonly Guid IID_IDispatchEx = new Guid("A6EF9860-C720-11D0-9337-00A0C90DCAA9");
    static readonly Guid IID_IPersist = new Guid("0000010C-0000-0000-C000-000000000046");
    static readonly Guid IID_IProvideClassInfo = new Guid("B196B283-BAB4-101A-B69C-00AA00341D07");
    static readonly Guid IID_IConnectionPointContainer = new Guid("B196B284-BAB4-101A-B69C-00AA00341D07");
    static readonly Guid IID_ISupportErrorInfo = new Guid("DF0B3D60-548F-101B-8E65-08002B2BD119");

    static void Main(string[] args)
    {
        Console.WriteLine("=== FSO Proxy Hole Tester ===\n");
        Console.WriteLine("Watch your debug window for gaps in logging!\n");

        // Create FSO - your hook should catch this
        Console.WriteLine("--- Creating FileSystemObject via Activator ---");
        Type fsoType = Type.GetTypeFromCLSID(CLSID_FSO);
        dynamic fso = Activator.CreateInstance(fsoType);
        Console.WriteLine($"FSO created: {fso.GetType()}\n");

        // Test 1: Basic IDispatch call (should be logged)
        Console.WriteLine("--- Test 1: Basic IDispatch call ---");
        Console.WriteLine("Calling fso.BuildPath('C:\\\\', 'test.txt')...");
        string path = fso.BuildPath("C:\\", "test.txt");
        Console.WriteLine($"Result: {path}");
        Console.WriteLine("CHECK: Did you see BuildPath in your log?\n");

        // Test 2: Get IUnknown pointers - check identity
        Console.WriteLine("--- Test 2: IUnknown Identity Check ---");
        IntPtr pUnk1 = Marshal.GetIUnknownForObject(fso);
        IntPtr pUnk2 = Marshal.GetIUnknownForObject(fso);
        Console.WriteLine($"IUnknown #1: 0x{pUnk1:X}");
        Console.WriteLine($"IUnknown #2: 0x{pUnk2:X}");
        Console.WriteLine($"Same? {pUnk1 == pUnk2} (should be true)");
        Marshal.Release(pUnk1);
        Marshal.Release(pUnk2);
        Console.WriteLine();

        // Test 3: QI for other interfaces - THIS IS THE HOLE
        Console.WriteLine("--- Test 3: QI Escape Test (THE BIG ONE) ---");
        IntPtr pFsoUnk = Marshal.GetIUnknownForObject(fso);

        var testIIDs = new (Guid iid, string name)[] {
            (IID_IDispatchEx, "IDispatchEx"),
            (IID_IPersist, "IPersist"),
            (IID_IProvideClassInfo, "IProvideClassInfo"),
            (IID_IConnectionPointContainer, "IConnectionPointContainer"),
            (IID_ISupportErrorInfo, "ISupportErrorInfo"),
        };

        foreach (var (iid, name) in testIIDs)
        {
            IntPtr pItf = IntPtr.Zero;
            Guid iidCopy = iid;
            int hr = Marshal.QueryInterface(pFsoUnk, ref iidCopy, out pItf);
            if (hr == 0)
            {
                // Now QI this interface for IUnknown
                IntPtr pItfUnk = IntPtr.Zero;
                Guid unkIid = IID_IUnknown;
                Marshal.QueryInterface(pItf, ref unkIid, out pItfUnk);

                bool escaped = pItfUnk != pFsoUnk;
                Console.WriteLine($"{name}: ptr=0x{pItf:X}, IUnknown=0x{pItfUnk:X} {(escaped ? "*** ESCAPED! ***" : "(ok)")}");

                if (escaped)
                {
                    Console.WriteLine($"  ^ This interface returned the REAL object's IUnknown!");
                    Console.WriteLine($"  ^ .NET now has a back-door to bypass your proxy!");
                }

                Marshal.Release(pItfUnk);
                Marshal.Release(pItf);
            }
            else
            {
                Console.WriteLine($"{name}: not supported (hr=0x{hr:X})");
            }
        }
        Marshal.Release(pFsoUnk);
        Console.WriteLine();

        // Test 4: Child object - GetDrive
        Console.WriteLine("--- Test 4: Child Object (GetDrive) ---");
        Console.WriteLine("Calling fso.GetDrive('C:')...");
        dynamic drive = fso.GetDrive("C:");
        Console.WriteLine($"Drive object: {drive.GetType()}");
        Console.WriteLine("CHECK: Was GetDrive logged? Is drive a proxy?\n");

        // Now call method on child - is IT proxied?
        Console.WriteLine("Calling drive.DriveType...");
        int driveType = drive.DriveType;
        Console.WriteLine($"DriveType: {driveType}");
        Console.WriteLine("CHECK: Was DriveType logged? If not, child escaped!\n");

        // Test 5: Enumerator - Drives collection
        Console.WriteLine("--- Test 5: Enumerator (Drives collection) ---");
        Console.WriteLine("Getting fso.Drives...");
        dynamic drives = fso.Drives;
        Console.WriteLine($"Drives collection: {drives.GetType()}");

        Console.WriteLine("Enumerating drives...");
        foreach (dynamic d in drives)
        {
            Console.WriteLine($"  Found drive: {d.DriveLetter}");
        }
        Console.WriteLine("CHECK: Did you see each drive access logged?\n");

        // Test 6: GetFolder and deeper nesting
        Console.WriteLine("--- Test 6: Deep Nesting (GetFolder -> SubFolders) ---");
        Console.WriteLine("Getting fso.GetFolder('C:\\\\')...");
        dynamic folder = fso.GetFolder("C:\\");
        Console.WriteLine($"Folder: {folder.Name}");

        Console.WriteLine("Getting folder.SubFolders...");
        dynamic subfolders = folder.SubFolders;
        Console.WriteLine($"SubFolders count: {subfolders.Count}");
        Console.WriteLine("CHECK: Is SubFolders proxied? Is Count logged?\n");

        // Test 7: Round-trip - object returning itself
        Console.WriteLine("--- Test 7: ParentFolder Round-trip ---");
        try
        {
            dynamic sub = null;
            foreach (dynamic s in subfolders)
            {
                sub = s;
                break;
            }
            if (sub != null)
            {
                Console.WriteLine($"Got subfolder: {sub.Name}");
                Console.WriteLine("Getting sub.ParentFolder...");
                dynamic parent = sub.ParentFolder;
                Console.WriteLine($"Parent: {parent.Name}");
                Console.WriteLine("CHECK: Is ParentFolder the same proxy or did it escape?\n");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}\n");
        }

        // Test 8: CreateTextFile - tests returned object wrapping
        Console.WriteLine("--- Test 8: CreateTextFile (new object creation) ---");
        string testFile = System.IO.Path.GetTempFileName();
        Console.WriteLine($"Creating text file: {testFile}");
        dynamic textStream = fso.CreateTextFile(testFile, true);
        Console.WriteLine($"TextStream type: {textStream.GetType()}");

        Console.WriteLine("Calling textStream.WriteLine('test')...");
        textStream.WriteLine("test data");
        Console.WriteLine("CHECK: Was WriteLine logged?\n");

        Console.WriteLine("Calling textStream.Close()...");
        textStream.Close();

        // Cleanup
        try { System.IO.File.Delete(testFile); } catch { }

        // Test 9: OpenTextFile 
        Console.WriteLine("--- Test 9: OpenTextFile ---");
        string readFile = System.IO.Path.GetTempFileName();
        System.IO.File.WriteAllText(readFile, "line1\nline2\n");

        Console.WriteLine($"Opening: {readFile}");
        dynamic reader = fso.OpenTextFile(readFile, 1); // ForReading
        Console.WriteLine($"Reader type: {reader.GetType()}");

        Console.WriteLine("Calling reader.ReadLine()...");
        string line = reader.ReadLine();
        Console.WriteLine($"Read: {line}");
        Console.WriteLine("CHECK: Was ReadLine logged?\n");

        reader.Close();
        try { System.IO.File.Delete(readFile); } catch { }

        Console.WriteLine("=== Tests Complete ===");
        Console.WriteLine("\nSummary of likely holes in your proxy:");
        Console.WriteLine("1. QI for non-IDispatch interfaces returns raw pointers");
        Console.WriteLine("2. This breaks COM identity (different IUnknown)");
        Console.WriteLine("3. .NET might cache the 'escaped' pointer and bypass you");
        Console.WriteLine("\nCheck your debug log for any gaps in coverage!");
    }
}
